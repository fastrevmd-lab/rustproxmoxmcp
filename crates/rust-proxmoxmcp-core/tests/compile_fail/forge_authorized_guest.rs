//! `AuthorizedGuest::new` is pub(crate); an external crate cannot call it.
fn main() {
    let _ = rust_proxmoxmcp_core::AuthorizedGuest::new(panic!(), panic!(), panic!());
}
