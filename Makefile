# Everyday targets. Every Python command goes through `uv run`, so nothing
# here needs an activated environment. `make` alone prints this list.
.DEFAULT_GOAL := help
SHELL := /bin/bash

UV ?= uv
COMPOSE ?= docker compose
MOCK ?= fw-paris-01_20260407_1000_techsupport.tgz

.PHONY: help setup test lint check mock screenshots build docker docker-rebuild clean distclean version

help: ## list the targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## create .venv from uv.lock (all groups) and install the pre-commit hook
	$(UV) sync --all-groups
	$(UV) run pre-commit install
	$(UV) run playwright install chromium

test: ## run the test suite
	$(UV) run pytest

lint: ## ruff
	$(UV) run ruff check .

check: lint test ## what CI runs: lint, tests, lockfile in sync with pyproject.toml
	$(UV) lock --check

mock: ## write a synthetic TSF to try the tool on (MOCK=<path>, LINES=<n>)
	$(UV) run tsf-anonymizer mock-tsf -o $(MOCK) $(if $(LINES),--lines $(LINES))

screenshots: ## regenerate docs/screenshots/ from the mock archive (Playwright)
	$(UV) run python scripts/docs-screenshots.py

build: ## wheel + sdist into dist/
	$(UV) build

docker: ## build the image and start the service (needs .env, see README)
	$(COMPOSE) up -d --build

docker-rebuild: ## same, from scratch: no layer cache, container recreated
	$(COMPOSE) build --no-cache
	$(COMPOSE) up -d --force-recreate

clean: ## remove caches and build output — never data/ or certs/
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache screenshots-ci
	find . -name __pycache__ -type d -prune -not -path './.venv/*' -exec rm -rf {} +

distclean: clean ## clean, plus the virtual environment
	rm -rf .venv

version: ## print the version (bump with: uv version --bump patch|minor|major)
	@$(UV) version --short
