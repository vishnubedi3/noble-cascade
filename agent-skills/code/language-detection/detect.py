#!/usr/bin/env python3
"""Standalone workspace inventory (informational, not a security scan)."""

from __future__ import annotations

import json
import os
from pathlib import Path

EXTENSIONS = {
    ".py": "Python", ".js": "JavaScript", ".cjs": "JavaScript",
    ".mjs": "JavaScript", ".ts": "TypeScript",
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".rb": "Ruby",
    ".php": "PHP", ".tf": "Terraform", ".yaml": "YAML/Config",
    ".json": "JSON/Config",
}
MANIFESTS = {
    "package.json": "Node.js / npm",
    "requirements.txt": "Python / pip",
    "pyproject.toml": "Python / setuptools",
    "go.mod": "Go Modules",
    "Cargo.toml": "Rust Cargo",
    "pom.xml": "Java Maven",
    "Dockerfile": "Docker Container",
}
EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", ".noble", ".venv"}


def detect_stack(root_dir: str | Path = ".") -> dict[str, list[str]]:
    languages: set[str] = set()
    frameworks: set[str] = set()
    for _, dirs, filenames in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for filename in filenames:
            suffix = Path(filename).suffix
            if suffix in EXTENSIONS:
                languages.add(EXTENSIONS[suffix])
            if filename in MANIFESTS:
                frameworks.add(MANIFESTS[filename])
    result = {"languages": sorted(languages), "build_systems": sorted(frameworks)}
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    detect_stack()
