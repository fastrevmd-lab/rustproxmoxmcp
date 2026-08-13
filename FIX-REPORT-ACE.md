# Fix Report: 0.1.1 Lab Findings A, C, E

## Summary

Three defects found in production (Proxmox cluster LXC 970, release 0.1.0) have been fixed using TDD:

- **Finding A**: Missing local file reports "malformed proxmox response"
- **Finding C**: No way to mint a usable token with guest grants via CLI
- **Finding E**: SIGHUP does not reload the token store

All fixes preserve existing behavior, pass 87 workspace tests, and satisfy `clippy --all-targets -- -D warnings`.

---

## Finding A: Misleading "malformed proxmox response" for local file errors

### Problem

Starting the service with a missing `token_secret_file` or `ca_pem_path` produced:
```
Error: build client for pve3
Caused by:
    malformed proxmox response: file /etc/proxmoxmcp/secrets/pve3.token: No such file or directory (os error 2)
```

The message is actively misleading: nothing was received from Proxmox, the server never got that far, and an operator reading this investigates their *cluster* when the problem is a local file.

### Fix

Added `ProxmoxError::Config` variant:
```rust
/// A local configuration or credential problem, before any request is made.
///
/// Distinct from [`ProxmoxError::Malformed`], which describes a response that
/// arrived in the wrong shape. Nothing has been sent when this is returned.
#[error("configuration error: {0}")]
Config(String),
```

Updated all local configuration/credential errors to use `Config` instead of `Malformed`:
- `Cluster::load_secret` - all four failure paths (both sources, neither source, env load, file load)
- `ProxmoxClient::new` - CA PEM read failure and endpoint validation

### TDD Evidence

**RED** (before fix):
```
test inventory::tests::missing_secret_file_reports_config_error_not_malformed_response ... FAILED
  assertion failed: error should not mention 'malformed'
  got: malformed proxmox response: file /nonexistent/pve3.token: No such file or directory (os error 2)

test client::tests::missing_ca_pem_reports_config_error_not_malformed_response ... FAILED
  assertion failed: error should not mention 'malformed'
  got: malformed proxmox response: ca_pem_path: No such file or directory (os error 2)
```

**GREEN** (after fix):
```
test inventory::tests::missing_secret_file_reports_config_error_not_malformed_response ... ok
test client::tests::missing_ca_pem_reports_config_error_not_malformed_response ... ok
```

Both tests verify the rendered message:
- Does NOT contain "malformed"
- DOES contain "configuration error" or "config"
- DOES contain the offending file path

### Files Changed

- `crates/rust-proxmoxmcp-core/src/error.rs` - added `Config` variant
- `crates/rust-proxmoxmcp-core/src/inventory.rs` - use `Config` in `load_secret`, added test
- `crates/rust-proxmoxmcp-core/src/client.rs` - use `Config` for CA PEM and endpoint, added test

---

## Finding C: No way to mint a usable token with guest grants via CLI

### Problem

`token add` accepts `--devices` and `--tools` but has no way to set the vendor grant. Combined with the rule that an authenticated token carrying no grant is refused for guest-addressed tools, **a token minted with the shipped CLI cannot call any guest tool at all.** The only workaround was hand-editing `tokens.json` to add a `grant` object.

### Fix

Added `--guests` and `--actions` flags to `ProxmoxCli`:
```rust
/// Guest selectors for token grant (comma-separated).
#[arg(long, value_delimiter = ',')]
pub guests: Vec<String>,

/// Actions this token may invoke (comma-separated).
#[arg(long, value_delimiter = ',', default_value = "read")]
pub actions: Vec<String>,
```

These flags must appear BEFORE the `token` subcommand (they're on `ProxmoxCli`, not inside `TokenAction`).

Created `build_token_grant()` function that:
1. Returns `None` for non-Add operations or when no guest fields are present
2. Validates each selector with `Selector::parse` at mint time, failing with a clear error naming the bad term
3. Parses action names (read, low, destructive) with clear errors for invalid values
4. Prints a note to stderr when `--guests` is omitted, explaining the token cannot use guest tools

Updated main.rs to call `run_with_grant::<ProxmoxGrant>` with the constructed grant instead of passing `None`.

### TDD Evidence

**Tests** (4 new tests in `crates/rust-proxmoxmcp/tests/token_grant.rs`):

1. `token_add_with_guests_and_actions_stores_grant` - verifies minting with `--guests vmid:600-699,tag:ci --actions read,low` stores the expected grant
2. `token_add_with_invalid_selector_fails_at_mint_time` - verifies `--guests site:emea` fails with "invalid --guests selector 'site:emea'"
3. `token_add_without_guests_prints_note_and_creates_grantless_token` - verifies note printed and token created with `grant: None`
4. `token_add_accepts_wildcard_guests` - verifies `--guests '*'` is accepted and stored

All tests verify by reloading `tokens.json` via `TokenStoreFile::load` and checking the stored grant.

**Example invocation**:
```bash
rust-proxmoxmcp --guests 'vmid:600-699,tag:ci' --actions read,low \
  token add --tokens-file /path/to/tokens.json --name my-token --devices '*' --tools '*'
```

**Note when omitted**:
```
Note: This token cannot use guest-addressed tools. Use --guests '*' or a selector (vmid:X, tag:Y, pool:Z) to grant guest access.
```

### Files Changed

- `crates/rust-proxmoxmcp/src/cli.rs` - added `guests` and `actions` fields
- `crates/rust-proxmoxmcp/src/main.rs` - added `build_token_grant()`, updated token command handling
- `crates/rust-proxmoxmcp/tests/token_grant.rs` - new test file with 4 integration tests

---

## Finding E: SIGHUP does not reload the token store

### Problem

The SIGHUP handler reloaded the cluster inventory and invalidated the guest cache, but not the token store. The documented workflow (mint a token, send SIGHUP) silently did not work: the new token authenticated only after a full `systemctl restart`. The journal cheerfully logged `cluster inventory reloaded` but said nothing about tokens.

### Fix

Extended `install_sighup_reload()` to accept an optional `token_store` parameter:
```rust
fn install_sighup_reload(
    clusters: Arc<ClusterInventory>,
    index: Arc<GuestIndex>,
    token_store: Option<Arc<TokenStoreFile<ProxmoxGrant>>>,
) -> std::io::Result<()>
```

The handler now:
1. Reloads cluster inventory (existing behavior)
2. Reloads token store if present (new behavior)
3. Logs failures of either reload without taking the server down
4. Logs token count on successful reload: `tracing::info!(tokens = count, "token store reloaded")`

Installed per-transport:
- **Stdio mode**: passes `None` for token store (no authentication in stdio mode)
- **HTTP mode**: passes the loaded `token_store` from `load_http_token_store()`

### Testability

The reload functionality is provided by `TokenStoreFile::reload()` from mecmcp 0.8.8, which is tested in that crate. This fix factored the reload into the SIGHUP handler (which is signal-driven and not easily unit-testable) by:

1. Using the existing tested `reload()` method from mecmcp
2. Ensuring both reloads run independently with proper error handling
3. Logging outcomes so operators can observe reload success/failure via journal

The change is structurally sound: if `reload()` works (it does, per mecmcp's tests), and the handler calls it (it does, per code review), then SIGHUP reloads tokens.

### Verification Approach

Manual verification on LXC 970 after deployment:
1. Add a token to `tokens.json`
2. Send SIGHUP to the service
3. Verify journal shows "token store reloaded" with new count
4. Verify new token authenticates without restart

### Files Changed

- `crates/rust-proxmoxmcp/src/main.rs` - updated `install_sighup_reload()` signature and implementation, moved handler installation per-transport

---

## Self-Review Findings

### Finding A
- ✅ New variant documented with clear distinction from Malformed
- ✅ All local config failures mapped to Config
- ✅ Error messages include file paths
- ✅ Tests verify rendered message content
- ✅ No changes to response-handling paths

### Finding C
- ✅ Flags documented with clear usage notes
- ✅ Selector validation at mint time prevents silent failures
- ✅ Note printed when --guests omitted explains limitation
- ✅ Wildcard '*' accepted and tested
- ✅ Invalid selectors fail with bad term named
- ✅ Invalid actions fail with clear error
- ✅ Tests verify stored grant structure
- ⚠️  Flags must come BEFORE `token` subcommand - this is a clap constraint from flattening mecmcp::Cli

### Finding E
- ✅ Both reloads run independently
- ✅ Failures logged but don't crash server
- ✅ Token count logged on success
- ✅ Stdio mode works without token store (passes None)
- ✅ HTTP mode passes loaded store
- ✅ Handler only installed once per transport
- ℹ️  Not directly unit-testable (signal-driven), but uses tested `reload()` method from mecmcp

---

## Test Summary

**Total**: 87 tests across workspace
- rust-proxmoxmcp-core: 47 tests (2 new for Finding A)
- rust-proxmoxmcp: 15 tests (4 new for Finding C)
- Integration tests: 25 tests

**New tests**:
- Finding A: 2 tests (missing secret file, missing CA PEM)
- Finding C: 4 tests (valid grant, invalid selector, no grant, wildcard)
- Finding E: 0 tests (signal-driven, verified via mecmcp's reload() tests)

**Clippy**: Clean with `-D warnings`

---

## Commits

1. `aaa01c5` Fix misleading "malformed proxmox response" for local file errors
2. `6b546a1` Add CLI support for minting tokens with guest grants  
3. `c7de5b4` Reload token store on SIGHUP
4. `eb27acc` Fix grant flags appearing in server help (Finding C refinement)

---

## Concerns

### Finding E: No Direct Unit Test

The SIGHUP handler is signal-driven and not easily unit-testable in isolation. The fix delegates to `TokenStoreFile::reload()`, which is tested in mecmcp 0.8.8.

**Verification plan**: Manual test on LXC 970 after deployment (add token, send SIGHUP, verify journal and authentication).

---

---

## Finding C Refinement: Grant Flags in Server Help

### Review Finding

After initial implementation, code review identified that `--guests` and `--actions` were sitting on the top-level `ProxmoxCli` struct, which meant they appeared in `rust-proxmoxmcp --help` as though they configured the server, but they were ignored on every server invocation. This violated the documented principle that "a flag that is present but ignored is worse than one that is absent, because the operator cannot tell."

### Solution: Pre-Parse Dispatch

**Intercept before parsing** rather than flatten grant flags onto ProxmoxCli.

Created `TokenCli` - a dedicated `#[derive(Parser)]` that owns the complete token surface:
```rust
pub struct TokenCli {
    #[command(subcommand)]
    pub command: TokenCommand,
}

pub enum TokenCommand {
    Add {
        tokens_file: PathBuf,
        name: String,
        devices: Vec<String>,
        tools: Vec<String>,
        guests: Vec<String>,      // ← Now here, not on ProxmoxCli
        actions: Vec<String>,     // ← Now here, not on ProxmoxCli
        provider: Option<String>,
        provider_tier: Option<String>,
        on_behalf_of: Option<String>,
        actor_type: Option<String>,
        server_pid: Option<i32>,
    },
    Revoke { ... },
    List { ... },
    Rotate { ... },
}
```

In `main()`, inspect `std::env::args()` before any parsing:
```rust
let args: Vec<String> = std::env::args().collect();
if args.get(1).map(String::as_str) == Some("token") {
    // Skip "token" and parse remainder as TokenCli
    let token_args = std::iter::once(args[0].clone())
        .chain(args.iter().skip(2).cloned())
        .collect::<Vec<_>>();
    let token_cli = TokenCli::parse_from(token_args);
    // Handle and return
}
// Otherwise parse ProxmoxCli and run server
```

### Benefits

1. **Grant flags off server help**: `rust-proxmoxmcp --help` shows only server flags
2. **Natural invocation order**: `rust-proxmoxmcp token add --name X --guests '*'` (flags after subcommand)
3. **Total interception**: `rust-proxmoxmcp token --help` shows complete token surface including grant flags
4. **No flattened CLI duplication**: The shared `mecmcp_runtime::cli::Cli` stays untouched

### Files Changed (Refinement)

- `crates/rust-proxmoxmcp/src/cli.rs` - removed grant fields from ProxmoxCli, added TokenCli and TokenCommand
- `crates/rust-proxmoxmcp/src/main.rs` - added pre-parse dispatch, token_command_to_action(), build_token_grant_from_add()
- `crates/rust-proxmoxmcp/tests/token_grant.rs` - updated all tests to use new invocation order

### Tests

All 4 existing token grant tests pass with the new invocation order (flags after subcommand). Verified:
- `token add --guests X --actions Y` works
- `token add` without `--guests` prints note and creates grantless token
- Invalid selectors fail at mint time with clear error
- Wildcard `*` accepted

---

## Conclusion

All three findings are fixed with TDD (where testable), preserve existing behavior, and pass the full test suite (87 tests). Finding C was refined after review to use pre-parse dispatch instead of flattened flags, removing grant flags from server help and enabling natural invocation order. Finding E relies on mecmcp's tested reload method plus manual verification post-deployment.
