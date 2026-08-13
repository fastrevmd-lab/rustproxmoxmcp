//! The type that makes stage-2 authorization unskippable.
//!
//! Stage 1 — tool and cluster scope — runs in the bearer boundary before any
//! I/O. Stage 2 needs a resolved guest, so it necessarily runs past the
//! boundary, in code a handler could forget to call.
//!
//! It therefore is not optional by construction. [`AuthorizedGuest`] has no
//! public constructor and no public fields; the only way to obtain one is
//! `crate::resolve::GuestIndex::authorize`, which runs the grant selector, the
//! action check and the protection resolution. Every mutating API in this crate
//! takes one. A handler that skips authorization does not compile.
//!
//! This is the same move `mecmcp` 0.8.1 made for audit: audited because it went
//! through the transport, not because someone remembered.

use crate::protect::Protection;
use crate::resolve::ResolvedGuest;
use crate::tier::Tier;

/// A guest that has passed stage-2 authorization for a specific tier.
#[derive(Debug, Clone)]
pub struct AuthorizedGuest {
    guest: ResolvedGuest,
    protection: Protection,
    tier: Tier,
}

impl AuthorizedGuest {
    /// Construct an authorized guest.
    ///
    /// Deliberately `pub(crate)`: `crate::resolve::GuestIndex::authorize` is the
    /// only caller, and it is the only place the checks live.
    pub(crate) fn new(guest: ResolvedGuest, protection: Protection, tier: Tier) -> Self {
        Self {
            guest,
            protection,
            tier,
        }
    }

    /// The resolved guest.
    #[must_use]
    pub fn guest(&self) -> &ResolvedGuest {
        &self.guest
    }

    /// The protection verdict observed at authorization time.
    #[must_use]
    pub fn protection(&self) -> &Protection {
        &self.protection
    }

    /// The tier this authorization was granted for.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }
}
