# CI pipeline — design

**Date:** 2026-08-13
**Status:** approved, ready for implementation planning

Continuous integration for `rustproxmoxmcp`, modelled on `rustjunosmcp`'s
pipeline and adapted where this repository genuinely differs.

---

## 1. Why

This repository has no CI. Not failing, not partial — absent: no `.github/`
directory, no workflow has ever run, and `statusCheckRollup` is empty on both
merged pull requests. `mergeStateStatus: CLEAN` on those PRs meant "nothing is
blocking the merge", which with no checks configured is what an empty gate looks
like rather than a passed one.

Everything that has gated this project so far — 97 tests, eleven review rounds,
a hand-run lab validation — depended on someone choosing to do it.

That is not hypothetical. Release 0.1 shipped with 91 passing tests, fifteen
gated task reviews and a whole-branch review, and still contained two defects
that made it **impossible to install**:

- the installer seeded `tokens.json` as a JSON object where the loader requires
  an array, so a fresh install could not mint its first token;
- `token add` had no way to set a token's guest grant, so no mintable token
  could call any guest-addressed tool.

Neither is a bug in the code. Both are properties of the software *as
delivered*, and nothing in the process ever delivered it before an operator did.
The reviews read diffs; the tests exercised libraries. The first time anything
ran the installer was on a container, twenty minutes before both blockers
surfaced.

The pipeline below exists to close that specific gap. `rustjunosmcp` already has
the job that would have caught both.

### Scope of the family it joins

| Repo | Workflows |
|---|---|
| `mecmcp` | `ci.yml`, `security.yml` |
| `rustjunosmcp` | `ci.yml`, `security.yml`, `release-image.yml` |
| `rustmistmcp` | `ci.yml`, `security.yml`, `release.yml` |
| **`rustproxmoxmcp`** | **none** |

---

## 2. Two prerequisites, settled

### `Cargo.lock` is committed

The repository currently gitignores it, matching `mecmcp` — which does so
deliberately, and compensates by pinning exact versions in `Cargo.toml` (the
`russh` CVE floor comment says as much).

That reasoning is right for a library and wrong here. This ships a **binary**,
and Rust's convention splits on exactly that line. Committing the lockfile means
CI builds the dependency set that was validated on the lab rig, `cargo audit`
has a real tree to audit, and a transitive crate publishing a bad version cannot
silently change what CI tested. It also makes `--locked` meaningful; without a
committed lockfile the flag asserts nothing.

The `mecmcp` git dependency stays pinned by `tag = "v0.8.8"`. Pinning by commit
`rev` as `rustmistmcp` does is stronger — a tag can move, a rev cannot — but the
lockfile already records the resolved commit, so the marginal gain does not
justify making every `mecmcp` upgrade a two-line edit.

### `gitleaks` runs as a binary, not as the action

`rustjunosmcp` uses `gitleaks/gitleaks-action`. That works there because
**`rustjunosmcp` is public**. `rustproxmoxmcp` is **private**, and the action
requires a `GITLEAKS_LICENSE` for organisation-owned private repositories. The
only secret in this organisation is `CODEX_API_KEY`.

Porting it verbatim would produce a job that fails for a licensing reason — the
"gate people learn to ignore" failure that `security.yml`'s own comment warns
about in a different context. The `gitleaks` tool itself is MIT licensed; only
the action wrapper is gated. So the job downloads a pinned release and runs
`gitleaks detect` directly.

---

## 3. Stage 1 — gate every pull request

Two workflows. Every action pinned to a commit SHA. `concurrency` groups so a
superseded run cancels. `RUSTFLAGS: -D warnings`.

### `ci.yml`

One job, `build-and-test`, on `ubuntu-24.04`:

```
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

Three deliberate differences from `rustjunosmcp`'s version:

- **`--locked` throughout.** The payoff from committing the lockfile: CI fails
  loudly if a build would change the dependency set rather than quietly
  resolving something new.
- **No per-package `fmt`/`clippy` lists.** The sibling names its four crates
  explicitly because its workspace holds members it does not want linted. This
  workspace has two crates, both ours, so `--all` is honest and keeps covering
  crates added later.
- **No feature matrix.** The sibling has real feature axes. This crate has one
  feature, `testing`, which is dev-only — so the useful check is the inverse:
  assert the release build does not pull it in, via a `cargo tree` grep for
  `rcgen`. That guards a property verified by hand at the end of 0.1.

**Toolchain.** `rust-toolchain.toml` pins `1.97.0`, so `dtolnay/rust-toolchain@stable`
would install stable and then rustup would immediately fetch 1.97.0 anyway. The
action is pinned to `1.97.0` to match the file.

### `security.yml`

Two jobs:

- **`gitleaks`** — pinned release binary, `gitleaks detect --no-banner`, full
  history (`fetch-depth: 0`).
- **`cargo-audit` + `cargo-deny`** — both installed with `cargo install --locked`
  rather than through marketplace actions. This copies the sibling's reasoning
  verbatim, because it learned it the hard way: `cargo-deny-action` builds its
  own image and depends on Docker Hub at run time, and has already gone red on
  registry timeouts with nothing wrong in the repository. `cargo deny check bans
  sources` against the committed `deny.toml`.

---

## 4. Stage 2 — the packaging job

### The installer is not modified

`rustjunosmcp` makes its installer testable with env-var hooks —
`JMCP_INSTALL_ROOT` to redirect writes, `SKIP_USER`, `SKIP_SYSTEMD_RELOAD`. CI
then runs it against a fake rootfs.

**This design rejects that approach**, and the reason is the same one that
motivates the whole pipeline. An `INSTALL_ROOT` hook means CI tests *the
installer in test mode*, not the installer. Every defect in 0.1.1 lived in
exactly that gap — between what was tested and what was delivered. Adding a
test-only code path to the one script whose real behaviour was just stabilised
would reintroduce the gap being closed.

Instead the installer runs **for real, as root, in a throwaway container**,
byte-for-byte as an operator runs it. The cost is a container pull per case
rather than a `mktemp -d`; on a cached runner that is under a minute for three
images, and it buys fidelity.

`packaging/lxc/install.sh` is unchanged by this work.

### What the suite asserts

Every row maps to a defect class this project has actually hit:

| Assertion | Catches |
|---|---|
| The tarball contains every required file | a packaging slip |
| Installs cleanly on `debian:13` | the baseline |
| The installer's own printed `token add` command runs **verbatim** and yields a token carrying a grant | the two 0.1 blockers, and the broken printed instruction |
| A re-run preserves `clusters.json` and `tokens.json` byte-for-byte (sha256 before/after) | credential clobbering on upgrade |
| A package with the binary removed is **refused**, leaving no state behind | half-installs |
| `debian:12` and `ubuntu:24.04` are **refused** | the Debian-13-only guarantee |

The last row is where this improves on the sibling. `rustjunosmcp` tests Debian
and Ubuntu as *positive* cases because it supports both. This installer
deliberately supports only Debian 13, so the same images become negative tests
proving the OS check fires. A guarantee nobody tests is a comment.

### `scripts/package-lxc.sh`

Replaces the by-hand tarball build: `cargo build --release --locked`, assemble
the tree, `tar`, print the sha256.

It carries one guard. GitHub runners are `ubuntu-24.04` (glibc 2.39) and the
target is Debian 13 (glibc 2.41), so a natively built binary runs there — older
glibc is forward-compatible. But a developer box on a rolling distribution can
be **newer**: the first 0.1 tarball was nearly built on glibc 2.44, which would
not have started on the target. So the script inspects the built binary's
maximum required `GLIBC_` symbol version and fails if it exceeds Debian 13's
2.41, directing the developer to build in a container instead.

That encodes a lesson that otherwise lives only in one session's memory.

### Files

```
.github/workflows/ci.yml                  build-and-test + packaging jobs
.github/workflows/security.yml            gitleaks + cargo-audit + cargo-deny
scripts/package-lxc.sh                    build, glibc guard, tarball
packaging/tests/package-smoke.sh          manifest + negative-package test
packaging/tests/distribution-smoke.sh     runs inside each container image
Cargo.lock                                committed
.gitignore                                Cargo.lock entry removed
```

---

## 5. Sequencing

Stage 1 and Stage 2 land as **separate pull requests**.

Stage 1 is small, touches no product code, and gates every subsequent PR —
including Stage 2's. Landing it first means Stage 2 is the first change this
repository has ever merged under an automated gate, which is a better proof than
any assertion in this document.

Stage 2 is larger, introduces three new scripts, and its own smoke tests are the
thing under test. It benefits from Stage 1 being green first.

---

## 6. Ruled out

**A release workflow.** `rustjunosmcp` and `rustmistmcp` both have one. This
project has no release process yet beyond a hand-built tarball, and a workflow
that publishes artefacts nobody consumes is speculation. Revisit when 0.2 has a
cutover story.

**Installer env-var hooks.** See §4; rejected on principle, not on cost.

**Testing against a live Proxmox cluster in CI.** The `testing` feature already
provides a TLS mock, and the end-to-end suite runs against it. Reaching a real
cluster from CI would need credentials in the runner and network access to the
lab, and would make an unrelated outage look like a code failure. Lab validation
stays a deliberate human step.
