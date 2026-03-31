.PHONY: install test lint check clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install fenceline in development mode
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"
	@echo ""
	@echo "Run 'source .venv/bin/activate' to activate the environment"

test: ## Run all tests
	.venv/bin/python -m pytest tests/ -v

lint: ## Run linter
	.venv/bin/python -m ruff check src/ tests/

check: ## Run fenceline check in current directory
	.venv/bin/fenceline check

simulate: ## Run attack simulations (safe, localhost only)
	cd testing && ./harness.sh

posture: ## Run quick security posture check
	bash tools/quick-check.sh

clean: ## Remove build artifacts
	rm -rf .venv .pytest_cache dist build *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
