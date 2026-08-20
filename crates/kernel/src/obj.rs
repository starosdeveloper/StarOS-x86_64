//! The kernel object table — the target of every capability, with generational
//! revocation.
//!
//! A [`Cap`](crate::cap::Cap) in a task's table does not name a kernel resource
//! directly; it holds an [`ObjectRef`] into this one global table. The
//! indirection is what makes *cross-task* revocation possible: [`revoke`] bumps
//! the generation of an object's slot, and from that moment **every** capability
//! that referenced it — in any task, including copies handed out over IPC — fails
//! to resolve, because [`get`] checks the generation the reference was minted
//! with against the slot's current one.
//!
//! Without that indirection a capability *is* the authority, and the only thing a
//! task can do is drop its own copy — which stops nobody else. The whole point of
//! phase 3.3's revocation criterion is the other case: a holder pulling an object
//! out from under a delegate that is still running and still holds a handle.
//!
//! This is the same design as `../kernel-Aarch64/crates/kernel/src/obj.rs`, with
//! one deliberate difference: only the object kinds this tree can actually mint
//! exist here. Devices, notifications, interrupts, shared and DMA buffers arrive
//! with phase 5 on this port, and an enum variant nothing constructs is a claim
//! the boot log would be entitled to make and could not back.

use alloc::vec::Vec;

use crate::sync::SpinLock;

/// A kernel resource a capability can name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Object {
    /// An IPC endpoint, by index into the endpoint table (see [`crate::ipc`]).
    Endpoint {
        /// Index into the kernel endpoint table.
        id: usize,
    },
}

/// A stable, revocable reference to an [`Object`]: which slot, and the generation
/// that slot held when the reference was created. A reference resolves only while
/// the slot's generation still matches — a [`revoke`] bumps it and invalidates
/// every outstanding reference at once.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectRef {
    /// Slot index in the object table.
    pub index: u32,
    /// Generation this reference was minted at.
    pub generation: u32,
}

/// One object-table slot: the live object (if any) and its current generation.
#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    object: Option<Object>,
}

/// The object table. Every operation below is short, self-contained and touches
/// nothing else, so the lock is simply held for the whole of it — and never
/// across a context switch, which is what keeps it from being a deadlock the
/// first time a blocking send runs underneath one.
///
/// It grows on demand rather than being a fixed array: the number of objects a
/// system needs is a property of what it finds and what user space builds, not of
/// a constant chosen here.
///
/// Growing is safe for this table in a way it is not for every table: a slot's
/// *index* is the only thing an [`ObjectRef`] holds, and a `Vec` never renumbers
/// the elements it already has. Slots are also reused rather than orphaned once
/// [`revoke`] empties them, so a workload that creates and destroys objects in a
/// loop settles at its true high-water mark instead of climbing forever.
static OBJECTS: SpinLock<Vec<Slot>> = SpinLock::new(Vec::new());

/// Create a new object, returning a reference to it, or `None` if the heap is
/// exhausted — or, for an endpoint, if its id names no slot in the IPC table.
pub fn create(object: Object) -> Option<ObjectRef> {
    // An endpoint object carries an id into a fixed table in `ipc`, and an id past
    // the end of that table makes an object that is perfectly well formed and that
    // no send or receive can ever use. Refusing here puts the failure on the line
    // that wrote the number, rather than on a server that starts, announces
    // itself, and then reports a receive failure with no id in sight.
    let Object::Endpoint { id } = object;
    if !crate::ipc::endpoint_exists(id) {
        return None;
    }

    let mut slots = OBJECTS.lock();
    // Prefer a revoked slot. Reusing it *keeps its generation*, which is what
    // stops a new object from silently answering to a stale reference minted for
    // the object that used to live there.
    if let Some((i, slot)) = slots.iter_mut().enumerate().find(|(_, s)| s.object.is_none()) {
        slot.object = Some(object);
        return Some(ObjectRef {
            index: i as u32,
            generation: slot.generation,
        });
    }
    // No free slot: grow. `try_reserve` rather than a plain `push` because the
    // caller is reachable from a syscall — user space must not be able to panic
    // the kernel by asking for one object too many.
    slots.try_reserve(1).ok()?;
    slots.push(Slot {
        generation: 0,
        object: Some(object),
    });
    Some(ObjectRef {
        index: (slots.len() - 1) as u32,
        generation: 0,
    })
}

/// Resolve `r` to its live [`Object`], or `None` if the slot is empty, out of
/// range, or has been revoked (its generation has moved past `r`'s).
#[must_use]
pub fn get(r: ObjectRef) -> Option<Object> {
    let slots = OBJECTS.lock();
    let slot = *slots.get(r.index as usize)?;
    if slot.generation == r.generation {
        slot.object
    } else {
        None
    }
}

/// Revoke the object `r` names: clear the slot and bump its generation so every
/// outstanding [`ObjectRef`] to it — in any task — stops resolving. Returns `true`
/// if `r` was live (a matching, present object); `false` if it was already gone
/// or stale, which makes a doubled revoke idempotent rather than a second event.
pub fn revoke(r: ObjectRef) -> bool {
    let mut slots = OBJECTS.lock();
    let Some(slot) = slots.get_mut(r.index as usize) else {
        return false;
    };
    if slot.generation == r.generation && slot.object.is_some() {
        slot.object = None;
        slot.generation = slot.generation.wrapping_add(1);
        true
    } else {
        false
    }
}

/// How many slots the table holds, and how many of them are live. For the boot
/// log: a revoke that frees a slot without the count of live objects falling is a
/// revoke that did not happen.
#[must_use]
pub fn census() -> (usize, usize) {
    let slots = OBJECTS.lock();
    let live = slots.iter().filter(|s| s.object.is_some()).count();
    (slots.len(), live)
}
