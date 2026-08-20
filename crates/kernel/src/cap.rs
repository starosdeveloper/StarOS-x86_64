//! Per-task capabilities — the microkernel's authority model.
//!
//! User space never names kernel objects by raw address or global id; it names
//! them by [`Handle`](staros_abi::Handle), an index into *its own* capability
//! table. A task can only act on objects it was explicitly granted, and can only
//! do what the capability permits — send versus receive is two different rights
//! on the same endpoint, not one. The kernel resolves the handle against the
//! caller's table on every syscall, so authority is unforgeable: holding handle 2
//! in your table says nothing about handle 2 in anyone else's.
//!
//! A capability is *rights + a reference*, not the object itself: it names its
//! target through an [`ObjectRef`] into the global [object table](crate::obj), so
//! the object can be revoked out from under every holder at once. The bits stored
//! here say only what the holder is *permitted* to do; whether the object still
//! exists is decided at use time by [`crate::obj::get`].
//!
//! Two facts about handles are worth stating because ring 3 depends on both:
//! handle 0 is reserved and names nothing, so a zeroed register is a bad handle
//! rather than someone's endpoint; and handles are assigned bottom-up and reused,
//! so a capability delegated into a table lands in its first free slot rather than
//! at a number the sender chose.

use alloc::vec::Vec;

use crate::obj::ObjectRef;

/// A single capability: which object it refers to and what the holder may do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cap {
    /// A rendezvous [`crate::ipc`] endpoint, with the directions permitted. A
    /// send-only capability cannot receive and vice versa.
    Endpoint {
        /// Reference to the endpoint object.
        obj: ObjectRef,
        /// The holder may `Send` on this endpoint.
        send: bool,
        /// The holder may `Recv` on this endpoint.
        recv: bool,
    },
}

impl Cap {
    /// The object this capability refers to, regardless of kind. Used by `Revoke`,
    /// which revokes the *object* for every holder rather than dropping one
    /// holder's slot.
    #[must_use]
    pub const fn object(&self) -> ObjectRef {
        match *self {
            Cap::Endpoint { obj, .. } => obj,
        }
    }

}

/// A task's capability table, indexed by handle value.
///
/// Grows as the task is granted more. Index 0 is present but permanently `None`:
/// it is the reserved null handle, so that a handle a task never received — a
/// zeroed register, an uninitialised variable — names nothing rather than naming
/// whatever landed in slot 0.
pub type CapTable = Vec<Option<Cap>>;

/// A capability table granting nothing — the default for kernel threads and the
/// base every user grant is built on. `None` if the heap is exhausted.
#[must_use]
pub fn empty_caps() -> Option<CapTable> {
    let mut caps = CapTable::new();
    caps.try_reserve_exact(1).ok()?;
    caps.push(None);
    Some(caps)
}

/// Install `cap` into `table` at the lowest free handle, returning that handle,
/// or `None` if the heap is exhausted.
///
/// Handles are assigned bottom-up from 1 and reused once freed, which is what
/// lets callers stop writing slot numbers: granting in order yields 1, 2, 3, and
/// a capability delegated later lands in the first gap.
pub fn install(table: &mut CapTable, cap: Cap) -> Option<u32> {
    // `skip(1)` keeps the null handle reserved; `position` then counts from the
    // slot after it, so the index is one more than it reports.
    if let Some(free) = table.iter().skip(1).position(Option::is_none) {
        table[free + 1] = Some(cap);
        return Some((free + 1) as u32);
    }
    table.try_reserve(1).ok()?;
    table.push(Some(cap));
    Some((table.len() - 1) as u32)
}

/// Resolve `handle` against `table`, or `None` if it names no live slot.
///
/// The null handle and any index past the end both answer `None`, and so does a
/// slot that was emptied — three different mistakes with one honest answer, which
/// is what the caller turns into `BadHandle`.
#[must_use]
pub fn resolve(table: &CapTable, handle: u32) -> Option<Cap> {
    if handle == 0 {
        return None;
    }
    *table.get(handle as usize)?
}
