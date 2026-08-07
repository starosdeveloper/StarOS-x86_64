//! The page tables the kernel is entered on.
//!
//! The walk itself lives in [`staros_paging`], which the kernel uses too; this
//! module is the loader's half of that crate's [`FrameSource`] — table frames
//! come from boot services, and a physical address is reached directly, because
//! the loader runs identity-mapped under firmware.
//!
//! Three mappings, and each of them has to exist for a different reason:
//!
//! * **Identity**, physical `0..max` at the same virtual address. The loader is
//!   running identity-mapped under firmware, and `mov cr3` takes effect on the
//!   *next* instruction — if the instruction after it is not mapped at the same
//!   address in the new tables, the machine triple-faults with nothing printed.
//!   This is also what makes the `RDI` value the kernel receives valid as both a
//!   physical and a virtual address, as `docs/SPEC.md` §2.4 promises.
//! * **Linear**, physical `0..max` at `0xFFFF_8000_0000_0000`. How the kernel
//!   reaches physical memory once it has left the identity map behind: page
//!   tables, ACPI tables, the framebuffer, the frame pool.
//! * **The kernel image** at `0xFFFF_FFFF_8000_0000`, one `PT_LOAD` segment at a
//!   time, with that segment's rights. W^X starts here rather than in phase 1.4,
//!   because a kernel that runs writable-and-executable even briefly has to be
//!   *made* W^X later, and "later" is where that gets forgotten.
//!
//! All three are scaffolding with a known end: phase 1.4 builds the kernel's own
//! tree, and the identity map — the one that keeps address zero readable — goes
//! away with these.

use staros_paging::{FrameSource, Mapper};

use crate::alloc::{alloc_pages, Error, PAGE_SIZE};
use crate::efi::BootServices;

// The address-space layout is a term of the hand-off, not a private choice of
// the loader, so both constants come from the contract crate the kernel also
// reads them from. Re-exported here because this is the module that uses them.
pub use staros_bootinfo::{KERNEL_VMA, PHYS_MAP_BASE};
pub use staros_paging::Rights;

/// Table frames from boot services, addressed identity-mapped.
struct BootServiceFrames<'a> {
    bs: &'a BootServices,
    /// The first allocation failure, kept because [`FrameSource`] can only say
    /// `None` and the firmware's status code is worth more than that.
    failure: Option<Error>,
}

// SAFETY: `alloc_pages` returns a page-aligned, zeroed, exclusively owned 4 KiB
// page from boot services; the loader runs identity-mapped, so a physical
// address is a valid pointer, and it stays valid across further allocations.
unsafe impl FrameSource for BootServiceFrames<'_> {
    fn alloc_table(&mut self) -> Option<u64> {
        // SAFETY: `bs` is the live boot-services table, as `PageTables::new`
        // requires of its caller.
        match unsafe { alloc_pages(self.bs, "allocate page table", 1) } {
            Ok(page) => Some(page),
            Err(e) => {
                self.failure.get_or_insert(e);
                None
            }
        }
    }

    fn table(&mut self, phys: u64) -> *mut u64 {
        phys as *mut u64
    }
}

/// A four-level page-table tree under construction.
pub struct PageTables<'a> {
    frames: BootServiceFrames<'a>,
    root: u64,
    gib_pages: bool,
}

impl<'a> PageTables<'a> {
    /// Allocate an empty PML4 and probe for 1 GiB page support.
    ///
    /// # Errors
    /// Propagates an allocation failure.
    ///
    /// # Safety
    /// `bs` must be live boot services, and the machine identity-mapped.
    pub unsafe fn new(bs: &'a BootServices) -> Result<Self, Error> {
        let mut frames = BootServiceFrames { bs, failure: None };
        let gib_pages = gib_pages_supported();
        let root = Mapper::new(&mut frames, gib_pages).map(|m| m.root());
        let root = match root {
            Ok(root) => root,
            Err(e) => return Err(frames.failure.take().unwrap_or_else(|| Error::own(e.as_str()))),
        };
        Ok(Self { frames, root, gib_pages })
    }

    /// The value to load into `CR3`.
    #[must_use]
    pub const fn cr3(&self) -> u64 {
        self.root
    }

    /// Whether 1 GiB pages will be used for the large maps.
    #[must_use]
    pub const fn uses_gib_pages(&self) -> bool {
        self.gib_pages
    }

    /// Map `size` bytes of physical memory at `phys` to virtual `virt`.
    ///
    /// # Errors
    /// Propagates allocation failures, and refuses a misaligned request rather
    /// than silently rounding it — a rounded mapping either exposes memory the
    /// caller did not ask for or omits memory it did.
    ///
    /// # Safety
    /// `bs` must be live; the tree must not be in use by the CPU yet.
    pub unsafe fn map(
        &mut self,
        _bs: &BootServices,
        virt: u64,
        phys: u64,
        size: u64,
        rights: Rights,
    ) -> Result<(), Error> {
        debug_assert!(size.is_multiple_of(PAGE_SIZE) || size == 0);
        let mut mapper = Mapper::adopt(self.root, &mut self.frames, self.gib_pages);
        let result = mapper.map(virt, phys, size, rights);
        // An out-of-frames error means the firmware refused an allocation, and
        // its own status code says more about why than "no free frame" does.
        result.map_err(|e| self.frames.failure.take().unwrap_or_else(|| Error::own(e.as_str())))
    }
}

/// Whether CPUID reports 1 GiB pages (`PDPE1GB`, leaf `0x8000_0001`, EDX bit 26).
fn gib_pages_supported() -> bool {
    // The extended leaf is checked for existence first: a CPU without extended
    // leaves returns the highest *basic* leaf instead of failing, so bit 26 would
    // be read out of an unrelated result.
    let max = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    if max < 0x8000_0001 {
        return false;
    }
    core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 26) != 0
}

/// Set `EFER.NXE` so the `NX` bit in these tables means "no execute" instead of
/// "reserved bit set".
///
/// Order matters: with NXE clear, every entry carrying `PTE_NX` is a *reserved
/// bit violation*, so the first instruction fetch after `mov cr3` page-faults
/// with no IDT to catch it. Called before the tables are loaded, never after.
///
/// # Safety
/// Ring 0 and long mode, which is where the loader runs.
pub unsafe fn enable_no_execute() {
    const IA32_EFER: u32 = 0xC000_0080;
    const NXE: u64 = 1 << 11;
    // SAFETY: EFER exists on every x86-64 CPU; setting NXE only changes the
    // meaning of a bit no current mapping uses.
    unsafe {
        let (lo, hi): (u32, u32);
        core::arch::asm!("rdmsr", in("ecx") IA32_EFER, out("eax") lo, out("edx") hi,
                         options(nomem, nostack, preserves_flags));
        let efer = (u64::from(hi) << 32 | u64::from(lo)) | NXE;
        core::arch::asm!("wrmsr", in("ecx") IA32_EFER, in("eax") efer as u32,
                         in("edx") (efer >> 32) as u32,
                         options(nomem, nostack, preserves_flags));
    }
}
