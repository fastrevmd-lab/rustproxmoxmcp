## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --locked -- -D warnings` passes
- [ ] `cargo build --workspace --locked` and `cargo test --workspace --locked` pass
- [ ] Tests added or updated for this change, and they fail against the old code
- [ ] `cargo audit` and `cargo deny check bans sources` are clean, or any new advisory/license exception is called out below
- [ ] No secrets, credentials, real cluster hostnames, VMIDs, or real device/config data in code, tests, fixtures, or this description — synthetic examples only
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] Does this touch a device-facing config or command path (e.g. `clusters.json`/`tokens.json` loading, the tool catalog, or anything that reaches the Proxmox API)? If so, describe the blast radius below
- [ ] If this touches a path that can act on a cluster/guest: deterministic code decides (plan → approve → apply, scope/protection checks), not a model output

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
