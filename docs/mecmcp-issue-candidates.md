# `mecmcp` issue candidates found while building rustproxmoxmcp 0.1

`mecmcp` is consumed read-only at `v0.8.8`. Nothing below was patched locally;
each is written up here to be filed against `fastrevmd-lab/mecmcp`.

Ordered by consequence.

---

## 1. `cli_validate` is opt-in, so a consumer can bind unauthenticated to the LAN

**Severity: high. Found by review, in this repo, after the code was written and
passing its tests.**

`mecmcp_runtime::cli_validate::validate` refuses exactly the two configurations
that matter:

- `cli_validate.rs:94` — streamable HTTP with neither `--tokens-file` nor
  `--allow-no-auth`
- `cli_validate.rs:97` — `--allow-no-auth` on a non-loopback bind

Both are correct. Neither runs unless the consumer remembers to call `validate`,
and nothing in the crate makes that call necessary. `rustproxmoxmcp`'s `main.rs`
did not call it, compiled, passed its tests, and would have served
`--transport streamable-http --host 0.0.0.0` with no authentication and no Host
allowlist. That is the deployment shape every server in this family ships in.

This is the same class of defect `mecmcp` 0.8.1 fixed for audit — "audited
because it went through the transport, not because someone remembered" — and
0.8.3's `client_name` bug, where the propagation was correct and unreachable
because the assembly never wired it.

**Suggested fix.** Make the validation unskippable rather than advisory. Options,
roughly in order of preference:

1. `build_streamable_http_router` calls `validate` itself, taking whatever it
   needs from `HttpTransportConfig`. The router builder already owns the
   host/origin policy and knows whether a bearer boundary was attached, which is
   most of what the check needs.
2. A type-state: `Cli` is not directly usable by the transport; `validate`
   consumes it and returns a `ValidatedCli` that the transport requires. The
   compiler then refuses the unvalidated path.
3. Failing both, a prominent note in `docs/PACKAGING.md` and the crate docs that
   a consumer MUST call it — weakest, since it is exactly the "remember to" that
   already failed here.

Option 1 or 2 would have made this impossible rather than merely documented.

---

## 2. The README's 0.6.0 upgrade notes now describe a double-apply

**Severity: medium. Actively misleading rather than merely stale.**

The README's "Upgrading to 0.6.0" section documents the consumer applying the
boundary and the IP rate limit by hand:

```rust
let app = apply_bearer_boundary(app, boundary, accounting);
let app = apply_ip_rate_limit(app, &limits); // outermost: runs first
```

with the accompanying note that "per-IP rate limiting is the one layer the
consumer still applies itself". That was true at 0.6.0. As of 0.7.0's transport
assembly it is not: `build_streamable_http_router` applies the bearer boundary
at `server.rs:423` and the IP rate limit at `server.rs:459`, and constructs the
`BoundaryAccounting` via its own `authenticated_accounting`.

A consumer following the 0.6.0 notes on 0.8.8 gets both layers twice — halving
the effective per-IP budget and stacking the boundary. Nothing fails loudly.

This is not hypothetical: the implementation plan for this repo was written
from those notes and carried the double-apply until it was caught by reading
`server.rs`.

**Suggested fix.** The 0.6.0 section is historical and readers reach it while
upgrading *through* it. Add a one-line superseded-by marker pointing at 0.7.0's
assembly, or move the manual pattern behind a "pre-0.7.0" heading. The
`apply_*` functions remaining public is fine — they are the building blocks —
but the narrative should not read as current guidance.

---

## 3. `WaiverRecord` cannot express an operator waiver

**Severity: low for 0.8.8; blocking for rustproxmoxmcp 0.3.**

`mecmcp_changeset::WaiverRecord` carries only `reason`, and the waived-approval
digest binds the literal string `"lab-mode-waived"`.

`rustproxmoxmcp` 0.3 needs two distinguishable override paths: a `--lab-mode`
flag for disposable lab rigs, and a **time-boxed operator waiver file** for
production — root-written, mode 0600, hot-reloaded on SIGHUP, naming specific
VMIDs with an expiry and a change ticket. The second is a controlled exception,
not a disabled control, and recording it as `lab-mode-waived` would misreport it
as the latter to anyone reading the change-set record afterwards.

**Suggested fix.** `WaiverRecord` gains a digest-bound `kind`
(`LabMode | Operator`), plus optional `expires_at` and `ticket`. Binding `kind`
into the digest is the part that matters — otherwise the distinction is
advisory and a record could be re-labelled after the fact.

Until then the consumer keeps its own waiver record and sets the change-set
waiver only when `--lab-mode` is genuinely on, which loses the linkage between
the approval record and the reason it was waived.

---

## Withdrawn after investigation

**A numeric-range `TargetValueShape` for `vmid:600-699`.** Initially looked
necessary so guest scoping could run in the preflight. It is not: `CallerScopes`
exposes only `token_name`, `devices` and `tools`, all opaque name sets, so even
a range-valued shape could not carry a guest selector into the preflight. The
selector belongs in the token's grant — `mecmcp-auth`'s documented vendor seam —
and is enforced after resolution. No shared-crate change is needed.
