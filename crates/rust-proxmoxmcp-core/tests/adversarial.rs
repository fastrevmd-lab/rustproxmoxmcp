//! Properties that must hold regardless of how the surface grows.
//!
//! Unlike the unit tests that verify specific behaviors, these assert structural
//! invariants: constraints that must remain true as new tools are added in future
//! releases. A violated invariant here means either broken authority (a mutating
//! tool reachable by wildcard), broken tooling (a URL template that cannot be
//! built), or degraded maintainability (the registry diff becomes unreviewable).

use rust_proxmoxmcp_core::{
    catalog::READ_TOOLS,
    tier::{tier_of, Tier, WRITE_TOOLS},
};

#[test]
fn every_catalog_path_templates_only_known_parameters() {
    const KNOWN: &[&str] = &["{node}", "{vmid}", "{kind}", "{storage}", "{upid}"];
    for tool in READ_TOOLS {
        let mut rest = tool.path;
        while let Some(open) = rest.find('{') {
            let close = rest[open..]
                .find('}')
                .unwrap_or_else(|| panic!("unterminated placeholder in {}", tool.name));
            let placeholder = &rest[open..=open + close];
            assert!(
                KNOWN.contains(&placeholder),
                "{} uses unknown placeholder {placeholder}",
                tool.name
            );
            rest = &rest[open + close + 1..];
        }
    }
}

#[test]
fn no_catalog_tool_uses_a_mutating_method() {
    for tool in READ_TOOLS {
        assert_eq!(
            format!("{:?}", tool.method).to_lowercase(),
            "get",
            "{} is not a GET",
            tool.name
        );
    }
}

#[test]
fn every_write_tool_classifies_as_low_or_destructive() {
    // The write registry is what excludes a tool from the wildcard scope. A
    // destructive tool missing from it is reachable by a "tools": ["*"] token,
    // and a read tool present in it narrows authority beyond what the spec
    // requires.
    for tool in WRITE_TOOLS {
        let tier = tier_of(tool).unwrap_or_else(|| panic!("unclassified tool {tool}"));
        assert!(
            matches!(tier, Tier::Low | Tier::Destructive),
            "{tool} is classified as {tier:?}, not Low or Destructive"
        );
    }
}

#[test]
fn the_write_registry_is_sorted_within_its_semantic_groups() {
    // Sorted groups keep the review diff readable when 0.2 adds to it, which is
    // the moment an omission actually costs something.
    //
    // The registry has three sections:
    // 1. Low-tier tools (up to but not including resize_disk)
    // 2. resize_disk (special case: tier depends on direction)
    // 3. Destructive tools (from delete_backup onwards)
    //
    // The destructive section has execute_vm_command intentionally placed at the
    // end because it is deferred to 0.5, so we check sortedness of everything
    // before it.

    // Find section boundaries
    let resize_pos = WRITE_TOOLS
        .iter()
        .position(|t| *t == "resize_disk")
        .expect("resize_disk present");
    // Destructive section starts right after resize_disk
    let destructive_start = resize_pos + 1;
    let execute_pos = WRITE_TOOLS
        .iter()
        .position(|t| *t == "execute_vm_command")
        .expect("execute_vm_command present");

    // Check low-tier section is sorted
    let low_tier = &WRITE_TOOLS[..resize_pos];
    let mut low_sorted = low_tier.to_vec();
    low_sorted.sort_unstable();
    assert_eq!(
        low_tier, low_sorted.as_slice(),
        "low-tier section is not sorted"
    );

    // Check destructive section (excluding execute_vm_command at the end) is sorted
    let destructive = &WRITE_TOOLS[destructive_start..execute_pos];
    let mut destructive_sorted = destructive.to_vec();
    destructive_sorted.sort_unstable();
    assert_eq!(
        destructive, destructive_sorted.as_slice(),
        "destructive section is not sorted"
    );

    // Verify execute_vm_command is the last element
    assert_eq!(
        execute_pos,
        WRITE_TOOLS.len() - 1,
        "execute_vm_command should be the last element (it's deferred to 0.5)"
    );
}

#[test]
fn no_read_tool_name_appears_in_the_write_registry() {
    // A read tool in WRITE_TOOLS would exclude it from wildcard scope for no
    // reason, narrowing a "tools": ["*"] grant beyond what the spec requires.
    for read_tool in READ_TOOLS {
        assert!(
            !WRITE_TOOLS.contains(&read_tool.name),
            "read tool {} appears in WRITE_TOOLS",
            read_tool.name
        );
    }
}

#[test]
fn every_guest_scoped_tool_templates_both_node_and_vmid() {
    // A tool marked needs_guest=true but missing {node} or {vmid} in its path
    // cannot be resolved correctly — the executor would fail to build the URL.
    for tool in READ_TOOLS.iter().filter(|t| t.needs_guest) {
        assert!(
            tool.path.contains("{node}"),
            "{} is needs_guest but lacks {{node}}",
            tool.name
        );
        assert!(
            tool.path.contains("{vmid}"),
            "{} is needs_guest but lacks {{vmid}}",
            tool.name
        );
    }
}

#[test]
fn authorized_guest_cannot_be_constructed_outside_the_crate() {
    // AuthorizedGuest::new is pub(crate), so external code cannot forge one and
    // bypass stage-2 authorization. This test uses trybuild to verify that a
    // compile-fail fixture correctly fails with a privacy error.
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/*.rs");
}
