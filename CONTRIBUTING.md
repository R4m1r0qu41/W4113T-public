# Contributing — CipherLayer Wallet

## License and DCO

Contributions are accepted under [Apache-2.0](LICENSE). Every commit must carry a
`Signed-off-by` line (`git commit -s`), certifying the [Developer Certificate of
Origin](https://developercertificate.org). Security findings: see `REVIEW-GUIDE.md`
in the family repo, or `SECURITY.md` in this repo.

## Ground rules

1. Read the README and `docs/adr/` first; the recorded architecture decisions apply to every contribution.
2. Wallet-first: browser implementation belongs in `../browser/` and is gated. Deferred scope (multi-chain, mobile, plugins, agents, MEV, token) needs an ADR before code.
3. Security-sensitive changes require tests and a requirements-matrix update. Architecture changes require an ADR (`docs/adr/`).

## Workflow

```bash
make bootstrap        # verify prerequisites, build
make fmt lint test    # required before every commit
make anvil-up && make test-integration   # required for pipeline changes
make demo             # end-to-end sanity check
```

- Small, auditable increments; one logical change per commit.
- Conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`), scoped and descriptive.
- No history rewriting, no force-push, no new remotes or pushes without operator authorization.
- Never commit secrets, keys, `.env`, keystores, or local databases. Use `.env.example` for configuration documentation.
- Pin dependencies; `Cargo.lock` is committed. Justify any new dependency in the PR/commit description (supply-chain surface).

## Code conventions

- Rust stable; `cargo fmt` and `cargo clippy -- -D warnings` must pass.
- Shared types live in `cipherlayer-types` and stay logic-free; crate boundaries in `README.md` are load-bearing — don't leak responsibilities across them.
- Security-critical values use typed representations (enums, `ChainId`, `Address`, `U256`), not free-form strings.
- Mark mocked security boundaries with a `MOCKED:` comment and keep `docs/security/prototype-limitations.md` current.
- Every state-machine transition must be auditable; new pipeline steps must emit audit events.

## Documentation

- Wire formats change in `schemas/` first (versioned), then in code.
- Keep Mermaid diagrams in `docs/architecture/` in sync with structural changes.
- Honest labeling: production-ready / prototype / experimental / mocked / deferred / theoretical. Never use "secure" as an unqualified status.
