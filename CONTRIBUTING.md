# Contributing to rustproxmoxmcp

Thanks for considering a contribution. rustproxmoxmcp is a Rust MCP server that fronts many Proxmox VE clusters behind one process — part of the [mechub](https://github.com/fastrevmd-lab) family of open-source, self-hosted network-security automation tooling. See [README.md](README.md) for what the server does.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach before writing code.
- This project follows one hard rule across the whole mechub fleet: **deterministic code decides, a model may explain, a human approves.** Nothing you contribute should let an LLM or other model output directly trigger a Proxmox-changing action — a VM/container create, delete, snapshot, or an `apply_proxmox_change_set` call. Models may draft, summarize, or explain; the plan → approve → apply pipeline and its digest/fingerprint checks are what decide, and a human is the one who approves an apply.

## Workspace layout

This is a Cargo workspace with two members (see `Cargo.toml`):

- `crates/rust-proxmoxmcp-core` — domain logic: inventory, guest resolution, authorization, the tool catalog. No server or transport code.
- `crates/rust-proxmoxmcp` — the binary. Assembles the transport (via `mecmcp-runtime`), loads the cluster inventory, and serves the catalog.

## Build and test

```sh
cargo build --workspace --locked
cargo test --workspace --locked
```

`rust-proxmoxmcp-core` has a non-default `testing` feature (pulls in `rcgen`, `rustls`, `tokio-rustls`, `tempfile`) that builds mock HTTPS servers for parts of the test suite. It is never compiled into the release binary; CI checks that separately (see below). To run those tests too:

```sh
cargo test -p rust-proxmoxmcp-core --locked --features testing
```

Lint and format, both required to pass in CI (`.github/workflows/ci.yml`):

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
```

Dependency, license, and secret checks, required to pass in CI (`.github/workflows/security.yml`):

```sh
cargo audit
cargo deny check bans sources
```

Secret scanning (`gitleaks`) also runs in CI on every push and PR; there's no separate local command beyond installing `gitleaks` yourself and running `gitleaks detect --no-banner` if you want to check before pushing.

### Release-build guard

CI also asserts that the `testing` feature's dependencies (notably `rcgen`) never leak into the release dependency tree of the `rust-proxmoxmcp` binary. If you touch feature flags or dependencies, check this doesn't regress:

```sh
cargo tree --package rust-proxmoxmcp --no-default-features --edges normal --locked
```

### Docker

If your change touches the `Dockerfile`, `ENTRYPOINT`/`CMD` split, or anything config-path related, build the image locally and confirm it still starts:

```sh
docker build -t rust-proxmoxmcp:dev .
```

CI's `docker-build` job additionally verifies that `--clusters-file`/`--tokens-file` config paths survive an operator passing `--host` at runtime (Docker replaces `CMD` but appends to `ENTRYPOINT`) — see the "Argv-survival regression guard" step in `.github/workflows/ci.yml` if you need to reproduce that locally.

## Commit and PR conventions

- Match the existing commit style: `type(scope): summary` (`fix(docker):`, `chore(deps):`, `ci:`, etc.) — see `git log` for examples.
- Keep PRs focused on one change.
- Fill out the PR template, including the exact commands you ran to verify the change.
- By opening a pull request, you're agreeing your contribution is licensed under this repository's [MIT license](LICENSE).

## Review process

Every pull request goes through a security review and a code review, then an independent test run, before anything merges. Only a maintainer merges — contributors, including anyone with write access, should not merge their own PR. CI (build, test, clippy, fmt, the release-build guard, Docker build, `cargo audit`, `cargo deny`, gitleaks secret scanning, and package conformance) must be green first.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and test data

Never commit real cluster endpoints, API token IDs/secrets, VMIDs tied to real infrastructure, or any other real device data — synthetic or sanitized fixtures and examples only (see the placeholder `pve3.example.org` style already used in `README.md` and `packaging/examples/`). If you find real data already committed anywhere in this repo, don't add to it — report it privately instead (see [SECURITY.md](SECURITY.md)).
