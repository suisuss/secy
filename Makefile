SHELL := /bin/bash

SREAD_SCRIPTS := sread/bin/sread \
	sread/lib/common.sh sread/lib/blocklist.sh sread/lib/redact.sh \
	$(wildcard sread/lib/modules/*.sh)

AGENT_SCRIPTS := $(wildcard agent/*.sh) $(wildcard agent/lib/*.sh)

TEST_SCRIPTS := $(wildcard sread/tests/*.sh) $(wildcard threatlab/*.sh)

ALL_SCRIPTS := $(SREAD_SCRIPTS) $(AGENT_SCRIPTS) $(TEST_SCRIPTS)

.PHONY: lint lint-sread lint-agent lint-tests test

lint: ## Run shellcheck on all shell scripts
	shellcheck -S warning $(ALL_SCRIPTS)

lint-sread: ## Run shellcheck on sread modules only
	shellcheck -S warning $(SREAD_SCRIPTS)

lint-agent: ## Run shellcheck on agent scripts only
	shellcheck -S warning $(AGENT_SCRIPTS)

lint-tests: ## Run shellcheck on test scripts only
	shellcheck -S warning $(TEST_SCRIPTS)

test: ## Run sread unit tests (no root required)
	@for t in sread/tests/test_*.sh; do echo "--- $$t ---"; bash "$$t"; done

help: ## Show available targets
	@grep -E '^[a-z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'
