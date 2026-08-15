# rustproxmoxmcp 0.3 — destructive operations under change-set control

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a destructive Proxmox operation reachable only through a change set whose approval is bound to the guest's identity and state at plan time, with the override living where the calling agent cannot reach it.

**Architecture:** `core` gains the vendor-side pieces — waiver file, UPID task polling, Proxmox fingerprint, preview rendering — with no knowledge of MCP or change sets. The binary crate owns `mecmcp-changeset`: it wraps `core`'s fingerprint and preview into a change set, gates apply on protection resolution plus waiver, and drives the Proxmox write through the task spine.

**Tech Stack:** Rust 2024, MSRV 1.88, `mecmcp-changeset` 0.10.0, `mecmcp-job`, `mecmcp-http`, `mecmcp-inventory`, `mecmcp-openapi`, `rmcp` 3.x.

**Spec:** `docs/superpowers/specs/2026-08-12-rustproxmoxmcp-design.md` — §4 safety spine, §8 tasks, §13 phasing. Read §4.1–§4.5 before Task 1.

## Scope — read this before starting

The spec's §4.3 lists **eight** destructive tools. This plan implements the machinery plus **one** of them, `delete_container`, end to end.

That is a deliberate cut, not an omission. The eight tools differ only in endpoint and argument shape; the thesis — *a destructive call is unreachable except through an approved, fingerprint-bound change set* — is proved once. Adding the other seven multiplies the review surface without testing anything new, and a reviewer cannot meaningfully gate a 4000-line diff in one sitting. They land as mechanical follow-ons once this shape is reviewed.

The `low` tier (spec §13's 0.2) is **not** built here either, with one exception: Task 3 builds the task/UPID spine that both tiers share, and Task 7 exercises it through the destructive path. A `low`-tier tool would prove the spine more cheaply, but it would need its own tool surface, scopes and tests — cost without progress toward the thesis.

## Global Constraints

- Rust 2024 edition, MSRV **1.88**.
- Workspace lints: `missing_docs = warn`, `unsafe_code = forbid`, `clippy::all = warn`, `unwrap_used = warn`. CI runs `-D warnings`, so treat every warning as an error, **including in tests** — use `.expect("reason")`.
- Every public item carries a doc comment.
- Five gates must pass: `cargo build --workspace --all-targets`, `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all --check`, `cargo doc --workspace --no-deps`.
- **Never hand-build a `WaiverRecord` or any mecmcp digest.** Call `waive_approval_operator` / `waive_approval`. A hand-built record fails validation on the next state load — this is a defect that shipped and was caught in mecmcp#275.
- No `grant_waiver` tool, no `add_cluster` tool, and **no `force` argument on any tool** (spec §4.2, §14). An override a caller can pass is not an override.
- `core` must not depend on `mecmcp-changeset` or `rmcp`. Vendor logic only.

---

### Task 1: The waiver file

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/waiver.rs`
- Modify: `crates/rust-proxmoxmcp-core/src/lib.rs` (add `pub mod waiver;`)
- Test: `crates/rust-proxmoxmcp-core/tests/waiver.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `WaiverFile::load(path: &Path) -> Result<WaiverFile, WaiverError>`, `WaiverFile::matching(&self, cluster: &str, vmid: u32, now_unix: u64) -> Option<&WaiverEntry>`, and `pub struct WaiverEntry { cluster: String, vmid: u32, until_unix: u64, reason: String, ticket: Option<String> }` with public accessors.

Spec §4.2 fixes the on-disk shape:

```jsonc
{ "version": 1, "waivers": [
  { "cluster": "pve3", "vmid": 905,
    "until": "2026-08-13T02:00:00Z",
    "reason": "decommission", "ticket": "CHG-4471" }
]}
```

- [ ] **Step 1: Write the failing tests**

```rust
// crates/rust-proxmoxmcp-core/tests/waiver.rs
use rust_proxmoxmcp_core::waiver::WaiverFile;
use std::io::Write;

/// Writes `body` to a temp file at mode 0600 and returns the path holder.
fn fixture(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    f.write_all(body.as_bytes()).expect("write");
    let mut perms = std::fs::metadata(f.path()).expect("metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
    std::fs::set_permissions(f.path(), perms).expect("chmod");
    f
}

const ONE: &str = r#"{"version":1,"waivers":[
  {"cluster":"pve3","vmid":905,"until":"2026-08-13T02:00:00Z",
   "reason":"decommission","ticket":"CHG-4471"}]}"#;

#[test]
fn a_waiver_matches_its_exact_target_inside_the_window() {
    let f = fixture(ONE);
    let w = WaiverFile::load(f.path()).expect("load");
    // 2026-08-13T01:00:00Z — inside the window.
    let hit = w.matching("pve3", 905, 1_786_237_200).expect("should match");
    assert_eq!(hit.reason(), "decommission");
    assert_eq!(hit.ticket(), Some("CHG-4471"));
}

#[test]
fn an_expired_waiver_does_not_match() {
    let f = fixture(ONE);
    let w = WaiverFile::load(f.path()).expect("load");
    // 2026-08-13T03:00:00Z — one hour past `until`.
    assert!(w.matching("pve3", 905, 1_786_244_400).is_none());
}

#[test]
fn a_waiver_does_not_match_a_different_guest_or_cluster() {
    let f = fixture(ONE);
    let w = WaiverFile::load(f.path()).expect("load");
    let inside = 1_786_237_200;
    assert!(w.matching("pve3", 906, inside).is_none(), "vmid must match exactly");
    assert!(w.matching("pve2", 905, inside).is_none(), "cluster must match exactly");
}

#[test]
fn a_group_readable_file_is_refused() {
    let f = fixture(ONE);
    let mut perms = std::fs::metadata(f.path()).expect("metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o640);
    std::fs::set_permissions(f.path(), perms).expect("chmod");
    let err = WaiverFile::load(f.path()).expect_err("0640 must be refused");
    assert!(format!("{err}").contains("0640"), "error should name the mode: {err}");
}

#[test]
fn an_unknown_version_is_refused() {
    let f = fixture(r#"{"version":2,"waivers":[]}"#);
    assert!(WaiverFile::load(f.path()).is_err(), "unknown version must be refused");
}

#[test]
fn a_missing_file_loads_as_empty_not_an_error() {
    let w = WaiverFile::load(std::path::Path::new("/nonexistent/waivers.json"))
        .expect("absent waiver file is not an error");
    assert!(w.matching("pve3", 905, 1_786_237_200).is_none());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core --test waiver`
Expected: FAIL — `unresolved import rust_proxmoxmcp_core::waiver`.

- [ ] **Step 3: Implement `waiver.rs`**

Read `crates/rust-proxmoxmcp-core/src/inventory.rs` first and reuse whatever hardened-loader helper it already uses for `clusters.json`; if it calls a `mecmcp` loader, call the same one rather than re-implementing the permission check. The mode check must reject group- or world-accessible files and name the offending mode in the error.

Parse `until` as RFC 3339 into a unix timestamp at **load** time. Store `until_unix: u64`. Evaluation takes `now_unix` as a parameter — never read the clock inside `matching`, so a test can pin time.

An absent file is an empty `WaiverFile`, not an error: a server with no waivers is the normal case.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core --test waiver`
Expected: PASS, 6 tests.

- [ ] **Step 5: Verify the guards are real**

For each of the three refusals — mode, version, expiry — delete the check, confirm its test fails, restore it, confirm it passes. Report all three. A guard whose test passes without it is not a guard.

- [ ] **Step 6: Commit**

```bash
git add crates/rust-proxmoxmcp-core/src/waiver.rs crates/rust-proxmoxmcp-core/src/lib.rs crates/rust-proxmoxmcp-core/tests/waiver.rs
git commit -m "feat(core): time-boxed operator waiver file (§4.2)"
```

---

### Task 2: Wire the override into protection, and add `--lab-mode`

**Files:**
- Modify: `crates/rust-proxmoxmcp-core/src/protect.rs`
- Modify: `crates/rust-proxmoxmcp/src/cli.rs`
- Test: `crates/rust-proxmoxmcp-core/tests/override.rs`

**Interfaces:**
- Consumes: `WaiverFile`, `WaiverEntry` from Task 1; the existing `protection_of(...)` and `Protection` in `protect.rs`.
- Produces: `pub enum Override { None, Waiver { reason: String, ticket: Option<String>, until_unix: u64 }, LabMode }` and `pub fn destructive_allowed(protection: &Protection, waivers: &WaiverFile, cluster: &str, vmid: u32, now_unix: u64, lab_mode: bool) -> Override`.

Spec §4.2's rule:

```
allowed := ¬protected ∨ waiver_matches(cluster, vmid, now) ∨ lab_mode
```

- [ ] **Step 1: Write the failing tests**

```rust
// crates/rust-proxmoxmcp-core/tests/override.rs
// Build `Protection` values through protect.rs's own constructors; read the file
// first and use whatever it exposes rather than constructing the enum by hand.

#[test]
fn an_unprotected_guest_needs_no_override() {
    let o = destructive_allowed(&unprotected(), &empty_waivers(), "pve3", 616, NOW, false);
    assert!(matches!(o, Override::None));
}

#[test]
fn a_protected_guest_with_no_override_is_refused() {
    // `destructive_allowed` reports the override; refusal is the caller's job when
    // the guest is protected and the override is None. Assert the discriminant.
    let o = destructive_allowed(&protected(), &empty_waivers(), "pve3", 905, NOW, false);
    assert!(matches!(o, Override::None), "no waiver, no lab mode -> no override");
}

#[test]
fn a_matching_waiver_overrides_protection_and_carries_its_reason() {
    let o = destructive_allowed(&protected(), &waivers_for("pve3", 905), "pve3", 905, NOW, false);
    match o {
        Override::Waiver { reason, ticket, .. } => {
            assert_eq!(reason, "decommission");
            assert_eq!(ticket.as_deref(), Some("CHG-4471"));
        }
        other => panic!("expected a waiver override, got {other:?}"),
    }
}

#[test]
fn an_expired_waiver_does_not_override() {
    let past = NOW + 86_400; // one day after `until`
    let o = destructive_allowed(&protected(), &waivers_for("pve3", 905), "pve3", 905, past, false);
    assert!(matches!(o, Override::None), "an expired waiver is not a waiver");
}

#[test]
fn lab_mode_overrides_protection() {
    let o = destructive_allowed(&protected(), &empty_waivers(), "pve3", 905, NOW, true);
    assert!(matches!(o, Override::LabMode));
}

#[test]
fn a_waiver_is_preferred_over_lab_mode_so_the_record_names_the_real_authority() {
    let o = destructive_allowed(&protected(), &waivers_for("pve3", 905), "pve3", 905, NOW, true);
    assert!(matches!(o, Override::Waiver { .. }),
        "with both available the specific, ticketed authority must be recorded");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core --test override`
Expected: FAIL — `destructive_allowed` not found.

- [ ] **Step 3: Implement `destructive_allowed` and the CLI flag**

In `protect.rs`, evaluate in this order: waiver first, then lab mode. The last test pins that ordering, and the reason is auditability — when both are available, the record should name the ticketed operator waiver, not the blanket flag.

In `crates/rust-proxmoxmcp/src/cli.rs`, add to `ProxmoxCli` (which already flattens `mecmcp_runtime::cli::Cli`):

```rust
    /// Run without two-person control for destructive operations.
    ///
    /// For a single-operator lab. No approver is invented: a waived change set
    /// records `approver: null` with a lab-mode waiver, so it stays
    /// distinguishable from one a second person reviewed.
    ///
    /// Spelled identically on every mecmcp server.
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Time-boxed operator waivers (spec §4.2). Mode 0600, service-owned.
    #[arg(long = "waivers-file", default_value = "/etc/proxmoxmcp/waivers.json")]
    pub waivers_file: PathBuf,
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core --test override && cargo build -p rust-proxmoxmcp`
Expected: PASS, 6 tests; binary builds.

- [ ] **Step 5: Prove `--lab-mode` reaches the binary**

Add a test asserting `ProxmoxCli::parse_from(["rust-proxmoxmcp", "--lab-mode"]).lab_mode` is true, and that the default is false. A flag that parses but never converts is the defect that took a sibling server down; it must be observable from the parsed struct.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: waiver and lab-mode override for the destructive tier (§4.2)"
```

---

### Task 3: The UPID task spine

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/task.rs`
- Modify: `crates/rust-proxmoxmcp-core/src/lib.rs`
- Test: `crates/rust-proxmoxmcp-core/tests/task.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub struct Upid { node: String, kind: String, id: String }` with `Upid::parse(&str) -> Result<Upid, TaskError>` and `fn node(&self) -> &str`; `pub enum TaskOutcome { Ok, Failed(String) }`; `pub fn classify_exit_status(status: &str) -> TaskOutcome`.

Spec §8: the UPID format is
`UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:`

- [ ] **Step 1: Write the failing tests**

```rust
// crates/rust-proxmoxmcp-core/tests/task.rs
use rust_proxmoxmcp_core::task::{classify_exit_status, TaskOutcome, Upid};

const REAL: &str = "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:";

#[test]
fn a_real_upid_parses_and_yields_its_node() {
    let u = Upid::parse(REAL).expect("parse");
    assert_eq!(u.node(), "pve2");
}

#[test]
fn the_node_comes_from_the_upid_not_the_caller() {
    // Guests migrate (spec §7): two 2026-08-12 renumbers were cross-node moves.
    // Polling must follow the UPID's node, never a caller-supplied one.
    let u = Upid::parse("UPID:pve3:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:")
        .expect("parse");
    assert_eq!(u.node(), "pve3");
}

#[test]
fn a_malformed_upid_is_refused_rather_than_guessed() {
    for bad in ["", "UPID:pve2", "not-a-upid", "UPID::::::::"] {
        assert!(Upid::parse(bad).is_err(), "must refuse {bad:?}");
    }
}

#[test]
fn ok_is_the_only_success_spelling() {
    assert!(matches!(classify_exit_status("OK"), TaskOutcome::Ok));
    for bad in ["WARNINGS: 1", "command 'x' failed: exit code 1", "interrupted by signal", ""] {
        match classify_exit_status(bad) {
            TaskOutcome::Failed(m) => assert_eq!(m, bad),
            TaskOutcome::Ok => panic!("{bad:?} must not be treated as success"),
        }
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core --test task`
Expected: FAIL — module `task` not found.

- [ ] **Step 3: Implement `task.rs`**

`Upid::parse` splits on `:` and requires the literal `UPID` prefix plus at least eight fields; reject anything shorter rather than indexing blindly. Keep `node`, `kind` (field 5) and `id` (field 6).

`classify_exit_status` treats **only** the exact string `"OK"` as success — spec §8 is explicit that Proxmox has several non-OK spellings and that interpreting them belongs to `core`, not `mecmcp-job`. `"WARNINGS: 1"` is a failure here: it means the task did not complete cleanly, and a destructive operation reporting warnings must not be recorded as a clean success.

Do **not** implement polling in this task. `mecmcp_job::poll_until_ready` is wired in Task 7 where there is a real task to follow; wiring it here would need a fake HTTP layer that Task 7 replaces.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core --test task`
Expected: PASS, 4 tests.

- [ ] **Step 5: Verify the success rule**

Change `classify_exit_status` to also accept `"WARNINGS: 1"`, confirm `ok_is_the_only_success_spelling` fails, restore, confirm it passes.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(core): UPID parsing and Proxmox exit-status classification (§8)"
```

---

### Task 4: The Proxmox fingerprint

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/fingerprint.rs`
- Modify: `crates/rust-proxmoxmcp-core/src/lib.rs`
- Test: `crates/rust-proxmoxmcp-core/tests/fingerprint.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub struct GuestState { pub cluster: String, pub vmid: u32, pub name: String, pub kind: String, pub node: String, pub status: String, pub tags: Vec<String>, pub config_digest: String, pub disks: Vec<(String, u64)> }` and `pub fn fingerprint(state: &GuestState) -> String` returning `sha256:<hex>`.

Spec §4.4, verified live 2026-08-15 — Proxmox's `digest` is present on both `lxc` and `qemu` configs, stable across reads, and moves on change:

```
sha256(cluster, vmid, name, type, node, status,
       sorted(tags), config_digest, sorted(disk_id, size_bytes))
```

- [ ] **Step 1: Write the failing tests**

```rust
// crates/rust-proxmoxmcp-core/tests/fingerprint.rs
use rust_proxmoxmcp_core::fingerprint::{fingerprint, GuestState};

fn base() -> GuestState {
    GuestState {
        cluster: "pve3".into(), vmid: 617, name: "test-labmode-proxmox".into(),
        kind: "lxc".into(), node: "pve2".into(), status: "running".into(),
        tags: vec!["test".into(), "disposable".into()],
        config_digest: "e94e30c44e1ead4df1c597c91406efe543c88494".into(),
        disks: vec![("rootfs".into(), 8_589_934_592)],
    }
}

#[test]
fn the_fingerprint_is_stable_for_identical_state() {
    assert_eq!(fingerprint(&base()), fingerprint(&base()));
    assert!(fingerprint(&base()).starts_with("sha256:"));
}

#[test]
fn tag_order_does_not_change_the_fingerprint() {
    let mut reordered = base();
    reordered.tags = vec!["disposable".into(), "test".into()];
    assert_eq!(fingerprint(&base()), fingerprint(&reordered),
        "tags are a set; ordering is not identity");
}

#[test]
fn every_component_changes_the_fingerprint() {
    let base_fp = fingerprint(&base());
    let mut cases: Vec<(&str, GuestState)> = Vec::new();
    let mut g = base(); g.cluster = "pve2".into();      cases.push(("cluster", g));
    let mut g = base(); g.vmid = 618;                    cases.push(("vmid", g));
    let mut g = base(); g.name = "renamed".into();       cases.push(("name", g));
    let mut g = base(); g.kind = "qemu".into();          cases.push(("kind", g));
    let mut g = base(); g.node = "pve3".into();          cases.push(("node", g));
    let mut g = base(); g.status = "stopped".into();     cases.push(("status", g));
    let mut g = base(); g.tags.push("protected".into()); cases.push(("tags", g));
    let mut g = base(); g.config_digest = "0".repeat(40); cases.push(("config_digest", g));
    let mut g = base(); g.disks = vec![("rootfs".into(), 1)]; cases.push(("disks", g));
    for (field, state) in cases {
        assert_ne!(base_fp, fingerprint(&state), "{field} must be bound into the fingerprint");
    }
}

#[test]
fn field_values_cannot_shift_a_boundary() {
    // The renumber case this exists for: a value containing the separator must not
    // let one guest impersonate another.
    let mut a = base(); a.name = "x".into();  a.node = "y|z".into();
    let mut b = base(); b.name = "x|y".into(); b.node = "z".into();
    assert_ne!(fingerprint(&a), fingerprint(&b),
        "a separator inside a value must not produce a colliding fingerprint");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core --test fingerprint`
Expected: FAIL — module `fingerprint` not found.

- [ ] **Step 3: Implement `fingerprint.rs`**

Hash `serde_json::to_vec` of a **tuple**, exactly as `mecmcp-changeset`'s `change_set_digest` does — a serialized tuple encodes lengths, so no field value can shift a boundary. Do **not** join with a separator: mecmcp#283 is an open issue about precisely that mistake in a neighbouring digest, and the last test above will fail if you make it.

Sort `tags` and `disks` before hashing so ordering is not identity.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core --test fingerprint`
Expected: PASS, 4 tests.

- [ ] **Step 5: Verify each binding**

Remove one field from the hashed tuple, confirm `every_component_changes_the_fingerprint` fails naming that field, restore. Do this for at least `config_digest` and `node` — the two that make the renumber case a refusal.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(core): Proxmox guest fingerprint over a serialized tuple (§4.4)"
```

---

### Task 5: The server-generated preview

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/preview.rs`
- Modify: `crates/rust-proxmoxmcp-core/src/lib.rs`
- Test: `crates/rust-proxmoxmcp-core/tests/preview.rs`

**Interfaces:**
- Consumes: `GuestState` from Task 4; `Override` from Task 2.
- Produces: `pub struct PreviewInput<'a> { pub state: &'a GuestState, pub protected: bool, pub protection_summary: &'a str, pub override_: &'a Override, pub snapshots: usize, pub latest_snapshot: Option<&'a str>, pub last_backup: Option<&'a str>, pub purge_disks: bool }` and `pub fn render_preview(input: &PreviewInput<'_>) -> String`.

Spec §4.5 fixes the shape:

```
DESTROY  pve3 / 907 vsrx-ci  (qemu, running)
  tags       ci, protected          ← PROTECTED
  node       pve2
  disks      scsi0 64G, scsi1 8G    (purge: yes)
  snapshots  3   latest: proven-0.19.0  (2026-08-11)
  backups    last: 2026-08-09 (3d ago), 2 retained
  waiver     none
  verdict    REFUSED — protected, no waiver
```

- [ ] **Step 1: Write the failing tests**

```rust
// crates/rust-proxmoxmcp-core/tests/preview.rs

#[test]
fn a_protected_guest_with_no_override_renders_a_refusal() {
    let text = render_preview(&protected_no_override());
    assert!(text.contains("PROTECTED"), "the protection must be visible: {text}");
    assert!(text.contains("REFUSED"), "the verdict must be REFUSED: {text}");
    assert!(text.contains("waiver     none"), "absence of a waiver must be stated, not omitted");
}

#[test]
fn a_waived_guest_names_the_authority_in_the_preview() {
    let text = render_preview(&protected_with_waiver());
    assert!(text.contains("CHG-4471"), "the ticket must appear: {text}");
    assert!(text.contains("decommission"), "the reason must appear: {text}");
    assert!(!text.contains("REFUSED"), "a waived plan is not refused: {text}");
}

#[test]
fn lab_mode_is_labelled_as_lab_mode_not_as_an_operator_waiver() {
    let text = render_preview(&protected_with_lab_mode());
    assert!(text.contains("lab-mode"), "lab mode must be named as such: {text}");
    assert!(!text.contains("CHG-"), "lab mode carries no ticket: {text}");
}

#[test]
fn backup_age_is_reported_and_never_enforced() {
    // Spec §4.5: enforcing a backup precondition would imply the backup restores,
    // and this estate has a documented counter-example (ssdf-clickhouse).
    let text = render_preview(&no_backup_at_all());
    assert!(text.contains("backups"), "backup line must always be present: {text}");
    assert!(!text.contains("REFUSED"), "a missing backup must not itself refuse: {text}");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p rust-proxmoxmcp-core --test preview`
Expected: FAIL — module `preview` not found.

- [ ] **Step 3: Implement `preview.rs`**

Render every line every time, including `waiver     none`. An omitted line reads as "not applicable"; a present line reading `none` is evidence the server looked.

Backup age is reported and never gates the verdict — assert this in code with a comment pointing at §4.5, because it will look like a missing check to a future reader.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p rust-proxmoxmcp-core --test preview`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): server-generated destroy preview (§4.5)"
```

---

### Task 6: Change-set wiring

**Files:**
- Modify: `crates/rust-proxmoxmcp/Cargo.toml` (add `mecmcp-changeset`)
- Modify: `crates/rust-proxmoxmcp/src/server/mod.rs`
- Create: `crates/rust-proxmoxmcp/src/server/change_set.rs`
- Test: `crates/rust-proxmoxmcp/tests/change_set.rs`

**Interfaces:**
- Consumes: `fingerprint`, `render_preview`, `destructive_allowed`, `WaiverFile` from Tasks 1–5.
- Produces: MCP tools `plan_proxmox_destroy`, `get_proxmox_change_set`, `approve_proxmox_change_set`, `apply_proxmox_change_set`.

The exact mecmcp 0.10.0 signatures — **use these verbatim, do not guess**:

```rust
ChangesetCoordinator::load(path: Option<&Path>, limits: OperationLimits,
                           approval_ttl: Duration, lab_mode: bool) -> Result<Self, CoordinatorError>

create_change_set<A: Serialize>(&self, device: String, actions: Vec<A>, owner: String,
                                expected_fingerprint: String, policy_signature: String)
                                -> Result<ChangeSetOutput, CoordinatorError>

approve_change_set(&self, change_set_id: String, device: String, approver: String,
                   expected_digest: String) -> Result<ChangeSetOutput, CoordinatorError>

waive_approval_operator(&self, change_set_id: String, device: String, owner: String,
                        expected_digest: String, kind: WaiverKind, reason: String,
                        expires_at_unix: Option<u64>, ticket: Option<String>)
                        -> Result<ChangeSetOutput, CoordinatorError>

waive_approval(&self, change_set_id: String, device: String, owner: String,
               expected_digest: String) -> Result<ChangeSetOutput, CoordinatorError>
```

`device` is the change-set's target key. Use `format!("{cluster}/{vmid}")` — the same value must be passed to every call for one change set, or lookups miss.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/rust-proxmoxmcp/tests/change_set.rs

#[tokio::test]
async fn planning_a_destroy_binds_the_fingerprint_and_returns_a_preview() {
    let h = handler_with_guest(617, /*protected*/ false);
    let planned = call(h, "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617})).await.expect("plan");
    assert!(planned["change_set_id"].is_string());
    assert!(planned["preview"].as_str().expect("preview").contains("DESTROY"));
    assert!(planned["expected_fingerprint"].as_str().expect("fp").starts_with("sha256:"));
}

#[tokio::test]
async fn applying_without_approval_is_refused() {
    let h = handler_with_guest(617, false);
    let planned = call(h.clone(), "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617})).await.expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    let err = call(h, "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster":"pve3","vmid":617})).await
        .expect_err("an unapproved change set must not apply");
    assert!(format!("{err}").to_lowercase().contains("approv"), "{err}");
}

#[tokio::test]
async fn the_planner_cannot_approve_its_own_change_set() {
    let h = handler_with_guest(617, false);
    let planned = call(h.clone(), "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617})).await.expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    let err = call(h, "approve_proxmox_change_set",
        json!({"change_set_id": id, "cluster":"pve3","vmid":617})).await
        .expect_err("self-approval must be refused");
    assert!(format!("{err}").to_lowercase().contains("self"), "{err}");
}

#[tokio::test]
async fn planning_a_protected_guest_without_an_override_is_refused() {
    let h = handler_with_guest(905, /*protected*/ true);
    let err = call(h, "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":905})).await
        .expect_err("protected without waiver must refuse");
    assert!(format!("{err}").to_lowercase().contains("protect"), "{err}");
}

#[tokio::test]
async fn a_fingerprint_that_moved_after_approval_refuses_the_apply() {
    // Spec §4.4's renumber case, as a test.
    let h = handler_with_guest(617, false);
    let planned = call(h.clone(), "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617})).await.expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    approve_as_second_principal(&h, id).await;
    h.move_guest_to_node(617, "pve3");           // config digest / node changes
    let err = call(h, "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster":"pve3","vmid":617})).await
        .expect_err("a moved guest must refuse the apply");
    assert!(format!("{err}").to_lowercase().contains("fingerprint"), "{err}");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p rust-proxmoxmcp --test change_set`
Expected: FAIL — the tools do not exist.

- [ ] **Step 3: Implement the four tools**

Read `crates/rustmistmcp/src/server/change_set.rs` in the sibling repo `/home/mharman/Projects/rustmistmcp` first — it is the closest working example of this exact shape, including how it stores and re-reads records.

`plan_proxmox_destroy` resolves the guest, computes the fingerprint (Task 4), renders the preview (Task 5), evaluates `destructive_allowed` (Task 2), and **refuses at plan time** if the guest is protected with no override. Then it calls `create_change_set` and, when an override applies, immediately waives:

- `Override::Waiver { reason, ticket, until_unix }` → `waive_approval_operator(..., WaiverKind::OperatorFile, reason, Some(until_unix), ticket)`
- `Override::LabMode` → `waive_approval(...)`
- `Override::None` → no waiver; the change set needs a genuine second principal.

Bind the preview into the record via `PreviewRecord` so the approver sees the server's own evidence, not the caller's claim.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p rust-proxmoxmcp --test change_set`
Expected: PASS, 5 tests.

- [ ] **Step 5: Verify each gate**

Sabotage each independently and confirm exactly one test fails per gate: (a) the protected-without-override refusal, (b) the self-approval refusal, (c) the fingerprint re-check at apply, (d) the approval requirement. Four sabotages, four results. Use `--no-fail-fast`, and confirm the build still compiles each time — a broken build produces no `FAILED` lines and reads as success.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: destructive change-set lifecycle for Proxmox guests (§4)"
```

---

### Task 7: `delete_container` end to end

**Files:**
- Create: `crates/rust-proxmoxmcp-core/src/guests.rs`
- Modify: `crates/rust-proxmoxmcp/src/server/change_set.rs`
- Test: `crates/rust-proxmoxmcp/tests/destroy.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–6; `Upid`, `classify_exit_status` from Task 3.
- Produces: `pub async fn destroy_container(client: &ProxmoxClient, node: &str, vmid: u32, purge: bool) -> Result<Upid, ProxmoxError>` in `core/guests.rs`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/rust-proxmoxmcp/tests/destroy.rs

#[tokio::test]
async fn an_approved_destroy_issues_the_delete_and_follows_the_task_to_completion() {
    let h = handler_with_guest(617, false);
    let planned = call(h.clone(), "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617})).await.expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    approve_as_second_principal(&h, id).await;
    h.script_task_completion("UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:", "OK");

    let applied = call(h.clone(), "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster":"pve3","vmid":617})).await.expect("apply");

    assert_eq!(applied["outcome"], "ok");
    assert!(applied["upid"].as_str().expect("upid").starts_with("UPID:"));
    let reqs = h.requests();
    assert!(reqs.iter().any(|r| r.method == "DELETE" && r.path.contains("/lxc/617")),
        "the DELETE must actually be issued: {reqs:?}");
}

#[tokio::test]
async fn a_task_that_ends_non_ok_is_reported_as_a_failure_not_a_success() {
    let h = handler_with_guest(617, false);
    let planned = call(h.clone(), "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617})).await.expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    approve_as_second_principal(&h, id).await;
    h.script_task_completion("UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:",
                             "command 'lxc-destroy' failed: exit code 1");
    let err = call(h, "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster":"pve3","vmid":617})).await
        .expect_err("a failed task must not report success");
    assert!(format!("{err}").contains("exit code 1"), "{err}");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p rust-proxmoxmcp --test destroy`
Expected: FAIL — no DELETE is issued.

- [ ] **Step 3: Implement the destroy and the task follow**

`destroy_container` issues `DELETE /nodes/{node}/lxc/{vmid}` with `purge` as a query parameter, and returns the parsed `Upid`. Resolve `node` from the cluster, never from the caller (§7).

In apply: issue the delete, persist the UPID into the operation record **before** polling (§8's indeterminate recovery depends on it), then poll `GET /nodes/{node}/tasks/{upid}/status` through `mecmcp_job::poll_until_ready`, mapping `running` → `Probe::Pending` and `stopped` → `Probe::Ready(exitstatus)`. Classify with `classify_exit_status` from Task 3.

Surface `PollError`'s three variants as three distinct errors — spec §8: *"job polling failed" tells an operator nothing about which of the three happened.*

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p rust-proxmoxmcp --test destroy`
Expected: PASS, 2 tests.

- [ ] **Step 5: Verify the UPID is persisted before polling**

Add a test that the operation record contains the UPID even when polling is then cancelled. Sabotage: move the persist to after the poll, confirm the test fails. This is the property that makes a crashed apply recoverable rather than merely detectable.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: delete_container under change-set control, following the UPID task"
```

---

### Task 8: Release 0.3.0

**Files:**
- Modify: `Cargo.toml` (workspace version), `README.md`, `docs/superpowers/specs/2026-08-12-rustproxmoxmcp-design.md` (§13 status)

- [ ] **Step 1: Bump the workspace version**

```bash
sed -i 's/^version      = "0.1.2"/version      = "0.3.0"/' Cargo.toml
grep -rn '0\.1\.2' Cargo.toml crates/*/Cargo.toml || echo "no stale pins"
```

Check for inter-crate dependency pins carrying the version inline and move those too — a sibling repo's release missed exactly that and failed CI.

- [ ] **Step 2: Write the README section**

State: what 0.3 adds (destructive tier under change-set control); that `--lab-mode` and `--waivers-file` now exist and what each means; that **only `delete_container`** is implemented of the eight destructive tools, with the rest to follow; and that there is deliberately no `grant_waiver` tool, because granting a waiver is a root operation.

- [ ] **Step 3: Update §13 of the design**

Mark 0.3 as shipped with the one-tool caveat, and record that 617 `test-labmode-proxmox` can now be enabled.

- [ ] **Step 4: Run every gate**

```bash
cargo build --workspace --all-targets
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo doc --workspace --no-deps
```

Run **all five**. `fmt` and `doc` were each missed for a whole branch in a sibling repo by running only `test` and `clippy`.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "chore(release): 0.3.0 — destructive operations under change-set control"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| §4.1 protection resolution | already built in 0.1 (`protect.rs::protection_of`) |
| §4.2 override — waiver file | 1, 2 |
| §4.2 override — `--lab-mode` | 2 |
| §4.3 tiers | already built in 0.1 (`tier.rs::tier_of`) |
| §4.4 Proxmox fingerprint | 4 |
| §4.5 server-generated preview | 5 |
| §8 UPID tasks | 3, 7 |
| §8 indeterminate recovery | 7 (step 5) |
| §13 release | 8 |

Deliberately **not** covered, and recorded in Scope above: the other seven destructive tools, and the whole `low` tier.

**Placeholder scan:** none. Two steps direct the implementer to read a neighbouring file rather than inlining code — `inventory.rs`'s hardened loader in Task 1 and the sibling `rustmistmcp/src/server/change_set.rs` in Task 6 — because both must match an existing construction exactly, and a guessed copy would compile while diverging.

**Type consistency:** `GuestState` is defined in Task 4 and consumed by Task 5. `Override` is defined in Task 2 and consumed by Tasks 5 and 6. `Upid` and `classify_exit_status` are defined in Task 3 and consumed by Task 7. `device` is `format!("{cluster}/{vmid}")` in every change-set call in Task 6.

**Two risks worth naming before execution:**

1. **Task 6 depends on test scaffolding that does not exist yet** — `handler_with_guest`, `call`, `approve_as_second_principal`, `script_task_completion`, `move_guest_to_node`, `requests()`. The repo has `crates/rust-proxmoxmcp/tests/common/`; Task 6's implementer must extend it, and that is real work folded into the task rather than a separate one. If it proves larger than the tools themselves, stop and say so rather than thinning the tests.
2. **`create_change_set` takes `policy_signature`**, which this server has no policy engine to produce. Pass a stable constant documenting that Proxmox has no policy compilation in 0.3, rather than inventing a value that looks meaningful.
