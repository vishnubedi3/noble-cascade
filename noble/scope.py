"""Deny-by-default target/action scope engine.

Policy is independent of untrusted requests. Patterns are parsed by target class;
we never do substring matching against a raw URL or repository identifier.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigurationInvalid, InvalidInput
from .models import PolicyDecision, Scope, ScopeDecision, Target, TargetKind, utcnow
from .targets import normalize_target

POLICY_PATH = (
    Path(__file__).resolve().parent.parent
    / "agent-skills/governance/scope-enforcement/scope-policy.yaml"
)


def _patterns(value: Any, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ConfigurationInvalid(f"scope.{key} must be a list of nonempty strings")
    return tuple(value)


def _hostname_match(pattern: str, host: str) -> bool:
    """A wildcard matches a proper subdomain only; never a lookalike suffix."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def _repo_match(pattern: str, canonical: str) -> bool:
    pattern, canonical = pattern.lower(), canonical.lower()
    if pattern.endswith("/*"):
        owner = pattern[:-2]
        return canonical.startswith(owner + "/") and canonical.count("/") == 1
    return canonical == pattern


def _forbidden_match(pattern: str, target: Target) -> bool:
    if target.kind is TargetKind.REPOSITORY:
        return _repo_match(pattern, target.canonical)
    if target.kind in (TargetKind.HOST, TargetKind.URL, TargetKind.IP):
        host = target.host or ""
        if pattern.endswith(".*"):
            return host.startswith(pattern[:-1].lower()) and len(host) > len(pattern) - 1
        return _hostname_match(pattern, host) or _hostname_match(pattern, target.canonical)
    if target.kind is TargetKind.PATH or target.kind is TargetKind.LOCAL_WORKSPACE:
        return os.path.normcase(target.canonical) == os.path.normcase(pattern)
    return target.canonical == pattern


def _parse_window(value: Any, key: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationInvalid(f"scope.{key} must be an ISO-8601 timestamp with timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigurationInvalid(f"scope.{key} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ConfigurationInvalid(f"scope.{key} must have an explicit timezone")
    return parsed.astimezone(timezone.utc)


def _within(path: str, root: str) -> bool:
    path_real = os.path.realpath(path)
    root_real = os.path.realpath(root)
    try:
        return os.path.commonpath((path_real, root_real)) == root_real
    except ValueError:
        return False


class ScopeEngine:
    """Enforce an operator's static authorized policy, then bind grants separately."""

    def __init__(self, policy: dict[str, Any], *, workspace_root: str | Path) -> None:
        if not isinstance(policy, dict) or policy.get("default_action") != "deny":
            raise ConfigurationInvalid("scope policy must explicitly set default_action: deny")
        raw = policy.get("scope")
        if not isinstance(raw, dict):
            raise ConfigurationInvalid("scope policy has no scope mapping")
        self.workspace_root = os.path.realpath(workspace_root)
        self.name = str(policy.get("policy_name", "unnamed-scope"))
        self.allowed_domains = _patterns(raw.get("allowed_domains"), "allowed_domains")
        self.allowed_repositories = _patterns(
            raw.get("allowed_repositories"), "allowed_repositories"
        )
        self.allowed_ip_ranges = _patterns(raw.get("allowed_ip_ranges"), "allowed_ip_ranges")
        self.allowed_directories = _patterns(raw.get("allowed_directories"), "allowed_directories")
        self.allowed_endpoints = _patterns(raw.get("allowed_endpoints"), "allowed_endpoints")
        self.allowed_actions = _patterns(
            raw.get("allowed_testing_methods"), "allowed_testing_methods"
        )
        self.forbidden_targets = _patterns(raw.get("forbidden_targets"), "forbidden_targets")
        self.forbidden_actions = _patterns(raw.get("forbidden_actions"), "forbidden_actions")
        self.approval_actions = _patterns(
            raw.get("approval_required_actions"), "approval_required_actions"
        )
        self.valid_from = _parse_window(raw.get("valid_from"), "valid_from")
        self.valid_until = _parse_window(raw.get("valid_until"), "valid_until")
        if self.valid_from and self.valid_until and self.valid_from > self.valid_until:
            raise ConfigurationInvalid("scope.valid_from is after valid_until")
        rate = raw.get("rate_limits", {})
        if not isinstance(rate, dict):
            raise ConfigurationInvalid("scope.rate_limits must be a mapping")
        self.requests_per_minute = int(rate.get("requests_per_minute", 60))
        self.max_concurrent_scans = int(rate.get("max_concurrent_scans", 2))
        if self.requests_per_minute < 1 or self.max_concurrent_scans < 1:
            raise ConfigurationInvalid("scope rate limits must be positive integers")
        for network in self.allowed_ip_ranges:
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError as exc:
                raise ConfigurationInvalid(f"invalid allowed IP range: {network}") from exc
        for pat in self.allowed_repositories:
            if pat == "*" or ("*" in pat and not pat.endswith("/*")):
                raise ConfigurationInvalid(f"unsafe repository allowlist entry: {pat}")
        for pat in self.allowed_domains:
            if pat == "*" or ("*" in pat and not pat.startswith("*.")):
                raise ConfigurationInvalid(f"unsafe domain allowlist entry: {pat}")
        self.allowed_roots = tuple(
            os.path.realpath(os.path.join(self.workspace_root, p) if not os.path.isabs(p) else p)
            for p in self.allowed_directories
        )
        if any(not _within(p, self.workspace_root) for p in self.allowed_roots):
            raise ConfigurationInvalid("allowed_directories cannot include paths outside workspace")

    @classmethod
    def from_file(
        cls, path: str | Path = POLICY_PATH, *, workspace_root: str | Path | None = None
    ) -> ScopeEngine:
        location = Path(path).resolve()
        try:
            policy = yaml.safe_load(location.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigurationInvalid(f"cannot read scope policy: {location}") from exc
        return cls(policy, workspace_root=workspace_root or POLICY_PATH.parent.parent.parent.parent)

    def snapshot(self, target: Target, action: str) -> Scope:
        """Snapshot a *checked* scope for the execution context."""
        decision = self.evaluate(target, action)
        if not decision.allowed:
            raise InvalidInput(f"scope cannot be snapshotted: {decision.reason}")
        return Scope(
            policy_name=self.name,
            allowed_targets=(target.canonical,),
            allowed_actions=(action,),
            denied_targets=self.forbidden_targets,
            denied_actions=self.forbidden_actions,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            network_destinations=(),  # network execution is disabled by default
        )

    def evaluate(
        self, target: Target, action: str, *, moment: datetime | None = None
    ) -> PolicyDecision:
        moment = moment or utcnow()
        if (self.valid_from and moment < self.valid_from) or (
            self.valid_until and moment > self.valid_until
        ):
            return PolicyDecision(ScopeDecision.DENY, "scope_time_window", "scope not active")
        if action in self.forbidden_actions:
            return PolicyDecision(ScopeDecision.DENY, "forbidden_action", "action forbidden")
        if action not in self.allowed_actions:
            return PolicyDecision(ScopeDecision.DENY, "action_allowlist", "action not allowed")
        for forbidden in self.forbidden_targets:
            if _forbidden_match(forbidden, target):
                return PolicyDecision(
                    ScopeDecision.DENY, "forbidden_target", "target explicitly excluded"
                )
        # Target scopes. Directory scope uses realpath, so symlinks outside the
        # workspace cannot be smuggled in via apparently innocent paths.
        if target.kind is TargetKind.REPOSITORY:
            for entry in self.allowed_repositories:
                if _repo_match(entry, target.canonical):
                    return PolicyDecision(ScopeDecision.ALLOW, "repository", "repository matched")
        elif target.kind in (TargetKind.HOST, TargetKind.URL):
            host = target.host or ""
            # A host pattern can allow a host/URL. Endpoints, if configured,
            # are *additional* restrictions, not a route around the host allowlist.
            for entry in self.allowed_domains:
                if _hostname_match(entry, host):
                    if (
                        target.kind is TargetKind.URL
                        and self.allowed_endpoints
                        and target.canonical not in self.allowed_endpoints
                    ):
                        return PolicyDecision(
                            ScopeDecision.UNKNOWN, "endpoint", "endpoint not listed"
                        )
                    return PolicyDecision(ScopeDecision.ALLOW, "domain", "host matched")
        elif target.kind in (TargetKind.IP, TargetKind.CIDR):
            try:
                allowed_networks = [
                    ipaddress.ip_network(n, strict=False) for n in self.allowed_ip_ranges
                ]
                if target.kind is TargetKind.CIDR:
                    candidate = ipaddress.ip_network(target.canonical, strict=False)
                    if any(
                        candidate.version == network.version
                        and candidate.prefixlen >= network.prefixlen
                        and candidate.network_address in network
                        for network in allowed_networks
                    ):
                        return PolicyDecision(
                            ScopeDecision.ALLOW, "ip_range", "CIDR is fully contained"
                        )
                else:
                    addr = ipaddress.ip_address(target.canonical)
                    if any(addr in network for network in allowed_networks):
                        return PolicyDecision(ScopeDecision.ALLOW, "ip_range", "address matched")
            except (TypeError, ValueError):
                pass
        elif target.kind in (TargetKind.PATH, TargetKind.LOCAL_WORKSPACE):
            for root in self.allowed_roots:
                if _within(target.canonical, root):
                    return PolicyDecision(ScopeDecision.ALLOW, "directory", "path is under root")
        return PolicyDecision(ScopeDecision.UNKNOWN, "default_deny", "target not in scope")

    def normalize_and_evaluate(self, raw: str, action: str) -> tuple[Target, PolicyDecision]:
        target = normalize_target(raw, workspace_root=self.workspace_root)
        return target, self.evaluate(target, action)
