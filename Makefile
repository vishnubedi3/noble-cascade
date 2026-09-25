.PHONY: setup verify certify replay release audit-pack benchmark platform trust-report governance baseline clean

setup: ## one-command setup (Phase 18)
	python -m pip install --require-hashes -r requirements-dev.lock
	python -m pip install -e . --no-deps
	noble doctor
	noble drift --baseline

verify: ## one-command verification (Phase 18)
	./verify-everything.sh

certify: ## one-command certification (Phase 18)
	noble certify

replay: ## one-command replay (Phase 18) — usage: make replay ID=lease-xxx
	noble replay $(ID) --json | head -n 100

release: ## one-command release (Phase 18)
	noble release --create
	noble release --verify
	cat release/RELEASE.json | head -n 50

help:
	@grep -E '^[a-z-]+:.*?##' Makefile | sort | awk 'BEGIN{FS=":.*?##"} {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

governance: ## repository governance audit (Master Prompt IV)
	noble governance --workflow-audit
	noble governance --baseline-verify
	noble governance --pr-analysis

baseline: ## regenerate repository security baseline (reviewed change only)
	noble governance --baseline-create
