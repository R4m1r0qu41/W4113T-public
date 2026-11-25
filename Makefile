# CipherLayer Wallet — developer command surface
# GNU Make 3.81 compatible (macOS default).

ANVIL_PORT ?= 8545
ANVIL_PID  := /tmp/cipherlayer-anvil.pid

.PHONY: help bootstrap fmt lint test test-integration audit sbom anvil-up anvil-down demo console W4113T docs-check family-check ci

help:
	@echo "CipherLayer Wallet targets:"
	@echo "  ci               local CI gate: fmt-check + lint + unit tests + docs-check"
	@echo "  bootstrap        check prerequisites and build the workspace"
	@echo "  fmt              format Rust code (cargo fmt)"
	@echo "  lint             clippy with warnings denied"
	@echo "  test             unit tests (no chain required)"
	@echo "  test-integration integration + security regression tests (requires anvil-up)"
	@echo "  audit            cargo audit (advisory DB), if installed"
	@echo "  sbom             CycloneDX SBOM via cargo-cyclonedx, if installed"
	@echo "  anvil-up         start local Anvil dev chain on port $(ANVIL_PORT)"
	@echo "  anvil-down       stop the Anvil dev chain"
	@echo "  demo             full vertical-slice demonstration (requires anvil-up)"
	@echo "  console          launch the W4113T interactive operator console (alias: W4113T)"
	@echo "  docs-check       verify required docs exist and internal links resolve"
	@echo "  family-check     Tier-0 offline invariant checks (review loop)"

bootstrap:
	@./scripts/check-prereqs.sh
	cargo build --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace --lib --bins

test-integration:
	CIPHERLAYER_INTEGRATION=1 cargo test --workspace --test '*' -- --test-threads=1

# RustSec advisory-database gate (cargo-audit). Deliberately NOT part of the
# offline `make ci` gate: fetching the advisory DB needs network, and `make
# ci` must stay runnable air-gapped and deterministic. Runs as its own CI job
# instead (.github/workflows/ci.yml) where network is expected.
audit:
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit --locked
	cargo audit

# CycloneDX SBOM (one JSON file per crate) via cargo-cyclonedx, written to
# target/sbom/ (gitignored — a generated artifact, not source).
sbom:
	@command -v cargo-cyclonedx >/dev/null 2>&1 || cargo install cargo-cyclonedx --locked
	@mkdir -p target/sbom
	cargo cyclonedx --format json --override-filename sbom
	@for f in crates/*/sbom.json; do \
		[ -f "$$f" ] && mv "$$f" "target/sbom/$$(basename $$(dirname $$f)).cdx.json"; \
	done
	@echo "SBOM written to target/sbom/"

anvil-up:
	@./scripts/anvil-up.sh $(ANVIL_PORT) $(ANVIL_PID)

anvil-down:
	@./scripts/anvil-down.sh $(ANVIL_PID)

demo:
	@./scripts/demo.sh

console:
	@cargo run -q -p cipherlayer-cli -- console

# The console's proper name — `make W4113T` launches it too.
W4113T: console

docs-check:
	@./scripts/docs-check.sh

# Local CI gate (no remote CI exists yet): everything that must pass before
# a commit is considered mergeable. Integration tests still require anvil-up
# and are run separately (make test-integration).
ci:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace --lib --bins
	@./scripts/docs-check.sh
	@./scripts/family-invariants.sh
	@echo "ci gate passed (integration suite runs separately: make anvil-up && make test-integration)"

# Tier-0 offline invariant checks alone (fast; also runs standalone from the
# root family-review.sh orchestrator). See CIPHERLAYER-FAMILY-GUIDE.md §7.
family-check:
	@./scripts/family-invariants.sh
