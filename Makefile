# IronContext by Altrusian Computer — top-level build & verification entry points.

CARGO         ?= cargo
PYTHON        ?= python3
NPM           ?= npm
RELEASE_BIN   := target/release/ironcontext
LARGE_FIXTURE := fixtures/large_manifest.json
BUDGET_MS     ?= 10
REDUCTION_PCT ?= 40

SIMILARITY    ?= 0.95

.PHONY: all build release test test-rust test-bench test-optimizer test-python \
        test-typescript test-action clean fmt fixtures help

help:
	@echo "IronContext — common targets:"
	@echo "  make build           Build the Rust workspace (debug)."
	@echo "  make release         Build the release binary at $(RELEASE_BIN)."
	@echo "  make test            Full verification: cargo + bench + optimizer + python + typescript + action."
	@echo "  make test-rust       cargo test only."
	@echo "  make test-bench      Latency gate (median < $(BUDGET_MS)ms)."
	@echo "  make test-optimizer  Optimizer gate (>= $(REDUCTION_PCT)% reduction, similarity >= $(SIMILARITY))."
	@echo "  make test-python     Python wrapper end-to-end tests."
	@echo "  make test-typescript TypeScript wrapper end-to-end tests (node --test)."
	@echo "  make test-action     Run the GitHub Action's flow locally + validate SARIF."
	@echo "  make fixtures        Regenerate fixtures/large_manifest.json."
	@echo "  make clean           Wipe target/ and __pycache__."

all: release

build:
	$(CARGO) build --workspace

release: $(RELEASE_BIN)

$(RELEASE_BIN):
	$(CARGO) build --release --workspace

fixtures:
	$(PYTHON) scripts/gen_large_fixture.py

test: test-rust test-bench test-optimizer test-python test-typescript test-action
	@echo ""
	@echo "IronContext: ALL GATES PASSED."

test-rust:
	$(CARGO) test --release --workspace

test-bench: $(RELEASE_BIN)
	$(RELEASE_BIN) bench $(LARGE_FIXTURE) --iterations 300 --budget-ms $(BUDGET_MS)

test-optimizer: $(RELEASE_BIN)
	$(RELEASE_BIN) optimize $(LARGE_FIXTURE) \
		--require-reduction-pct $(REDUCTION_PCT) \
		--require-similarity $(SIMILARITY) > /dev/null

test-python: $(RELEASE_BIN)
	PYTHONPATH=python $(PYTHON) -m unittest discover -s python/tests -v

test-typescript: $(RELEASE_BIN)
	cd typescript && $(NPM) install --silent --no-audit --no-fund && $(NPM) test

test-action: $(RELEASE_BIN)
	$(PYTHON) scripts/mock_action_run.py

fmt:
	$(CARGO) fmt --all

clean:
	$(CARGO) clean
	find python -type d -name __pycache__ -exec rm -rf {} +
	rm -rf typescript/node_modules typescript/dist typescript/dist-test
