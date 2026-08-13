//! Token minting with vendor grants.
//!
//! Verifies that `--guests` and `--actions` produce a token with the expected
//! grant, validated at mint time.

use mecmcp_auth::TokenStoreFile;
use rust_proxmoxmcp_core::{ProxmoxAction, ProxmoxGrant};
use std::process::Command;

#[test]
fn token_add_with_guests_and_actions_stores_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = dir.path().join("tokens.json");

    // Create an empty token store.
    std::fs::write(&tokens_path, r#"{"version":1,"tokens":[]}"#).expect("write");
    std::fs::set_permissions(
        &tokens_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("chmod");

    // Mint a token with guest scope and actions.
    // Grant flags now appear AFTER the subcommand.
    let output = Command::new(env!("CARGO_BIN_EXE_rust-proxmoxmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens_path.to_str().expect("path"),
            "--name",
            "test-token",
            "--devices",
            "*",
            "--tools",
            "*",
            "--guests",
            "vmid:600-699,tag:ci",
            "--actions",
            "read,low",
        ])
        .output()
        .expect("spawn");

    assert!(
        output.status.success(),
        "token add failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Reload the store and verify the grant.
    let store_file = TokenStoreFile::<ProxmoxGrant>::load(&tokens_path).expect("load");
    let store = store_file.store();
    let entries = store.entries();
    assert_eq!(entries.len(), 1, "expected exactly one token");

    let entry = &entries[0];
    assert_eq!(entry.name, "test-token");

    let grant = entry.grant.as_ref().expect("token should have a grant");
    assert_eq!(grant.guests, vec!["vmid:600-699", "tag:ci"]);
    assert_eq!(grant.actions, vec![ProxmoxAction::Read, ProxmoxAction::Low]);
}

#[test]
fn token_add_with_invalid_selector_fails_at_mint_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = dir.path().join("tokens.json");

    std::fs::write(&tokens_path, r#"{"version":1,"tokens":[]}"#).expect("write");
    std::fs::set_permissions(
        &tokens_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("chmod");

    let output = Command::new(env!("CARGO_BIN_EXE_rust-proxmoxmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens_path.to_str().expect("path"),
            "--name",
            "bad-token",
            "--devices",
            "*",
            "--tools",
            "*",
            "--guests",
            "site:emea", // Invalid selector
        ])
        .output()
        .expect("spawn");

    assert!(!output.status.success(), "should reject invalid selector");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid --guests selector"),
        "error should mention invalid selector, got: {stderr}"
    );
    assert!(
        stderr.contains("site:emea"),
        "error should name the bad term, got: {stderr}"
    );
}

#[test]
fn token_add_without_guests_prints_note_and_creates_grantless_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = dir.path().join("tokens.json");

    std::fs::write(&tokens_path, r#"{"version":1,"tokens":[]}"#).expect("write");
    std::fs::set_permissions(
        &tokens_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("chmod");

    let output = Command::new(env!("CARGO_BIN_EXE_rust-proxmoxmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens_path.to_str().expect("path"),
            "--name",
            "cluster-only-token",
            "--devices",
            "*",
            "--tools",
            "*",
            // No --guests
        ])
        .output()
        .expect("spawn");

    assert!(
        output.status.success(),
        "token add should succeed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot use guest-addressed tools"),
        "should print note about guest tools, got: {stderr}"
    );
    assert!(
        stderr.contains("--guests"),
        "note should mention --guests flag, got: {stderr}"
    );

    // Verify the token has no grant.
    let store_file = TokenStoreFile::<ProxmoxGrant>::load(&tokens_path).expect("load");
    let store = store_file.store();
    let entries = store.entries();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert!(entry.grant.is_none(), "token should have no grant");
}

#[test]
fn token_add_accepts_wildcard_guests() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = dir.path().join("tokens.json");

    std::fs::write(&tokens_path, r#"{"version":1,"tokens":[]}"#).expect("write");
    std::fs::set_permissions(
        &tokens_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("chmod");

    let output = Command::new(env!("CARGO_BIN_EXE_rust-proxmoxmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens_path.to_str().expect("path"),
            "--name",
            "admin-token",
            "--devices",
            "*",
            "--tools",
            "*",
            "--guests",
            "*",
        ])
        .output()
        .expect("spawn");

    assert!(
        output.status.success(),
        "token add failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let store_file = TokenStoreFile::<ProxmoxGrant>::load(&tokens_path).expect("load");
    let store = store_file.store();
    let entries = store.entries();
    let entry = &entries[0];
    let grant = entry.grant.as_ref().expect("grant");
    assert_eq!(grant.guests, vec!["*"]);
}
