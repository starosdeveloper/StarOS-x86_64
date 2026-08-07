//! Page allocation through boot services, and the error type the loader prints.
//!
//! Every allocation the loader makes is `EfiLoaderData`, which the kernel sees as
//! [`MemoryKind::LoaderReclaimable`] and deliberately does **not** hand to the
//! frame allocator at boot: the kernel image, the boot info and the memory map
//! all live in that memory and are still in use when the pool is built.
//!
//! [`MemoryKind::LoaderReclaimable`]: staros_bootinfo::MemoryKind::LoaderReclaimable

use core::fmt;

use crate::efi::{self, BootServices, Status};

/// Bytes per page, everywhere in this loader.
pub const PAGE_SIZE: u64 = 4096;

/// A failed step, named.
///
/// The pair matters more than either half: firmware returns the same
/// `EFI_NOT_FOUND` for a missing protocol and a missing file, and `stage` is what
/// separates "this machine has no GOP" from "there is no kernel on the ESP".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    /// What was being attempted.
    pub stage: &'static str,
    /// The `EFI_STATUS` returned, or 0 for a failure the loader itself detected.
    pub status: Status,
}

impl Error {
    /// A firmware call failed.
    #[must_use]
    pub const fn efi(stage: &'static str, status: Status) -> Self {
        Self { stage, status }
    }

    /// The loader rejected something itself; there is no firmware status.
    #[must_use]
    pub const fn own(stage: &'static str) -> Self {
        Self { stage, status: 0 }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.status == 0 {
            write!(f, "{}", self.stage)
        } else {
            // The low bits are the useful part; the error bit is set on every
            // failure and printing it in full just makes every code look alike.
            write!(f, "{} (EFI_STATUS {:#x})", self.stage, self.status & !(1 << 63))
        }
    }
}

/// Turn a status into a `Result`, attributing it to a stage.
///
/// # Errors
/// Returns [`Error`] when `status` has the error bit set.
pub fn check(stage: &'static str, status: Status) -> Result<(), Error> {
    if efi::is_error(status) {
        Err(Error::efi(stage, status))
    } else {
        Ok(())
    }
}

/// Allocate `pages` of zeroed `EfiLoaderData` and return its physical address.
///
/// Zeroed explicitly: `AllocatePages` promises nothing about contents, and both
/// callers depend on it — page tables must start empty, and a `.bss` tail is
/// defined to be zero.
///
/// # Errors
/// Propagates the firmware's status, tagged with `stage`.
///
/// # Safety
/// `bs` must be live boot services.
pub unsafe fn alloc_pages(
    bs: &BootServices,
    stage: &'static str,
    pages: usize,
) -> Result<u64, Error> {
    if pages == 0 {
        return Err(Error::own("zero-page allocation requested"));
    }
    let mut addr: u64 = 0;
    // SAFETY: caller guarantees live boot services; `addr` is a valid out-param.
    let status = unsafe {
        (bs.allocate_pages)(
            efi::ALLOCATE_ANY_PAGES,
            efi::memory_type::LOADER_DATA,
            pages,
            &raw mut addr,
        )
    };
    check(stage, status)?;
    // SAFETY: the firmware just handed us `pages` pages at `addr`, and the
    // loader runs identity-mapped, so the physical address is writable as-is.
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, pages * PAGE_SIZE as usize);
    }
    Ok(addr)
}

/// Pages needed to hold `bytes`.
#[must_use]
pub const fn pages_for(bytes: u64) -> usize {
    bytes.div_ceil(PAGE_SIZE) as usize
}
