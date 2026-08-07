//! The page tables the kernel is entered on.
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
//! Large pages carry the linear and identity maps: 64 GiB of 4 KiB entries would
//! be 128 MiB of page tables, which is more memory than the mapping is worth. The
//! kernel image itself is mapped 4 KiB at a time, because that is the granularity
//! its section rights are aligned to.

use crate::alloc::{alloc_pages, Error, PAGE_SIZE};
use crate::efi::BootServices;

/// Virtual base of the linear map of physical memory. Matches `docs/SPEC.md`
/// §3.1 and the constant the kernel will use to translate physical addresses.
pub const PHYS_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;
/// Virtual base of the kernel image, matching `crates/arch-x86_64/linker.ld`.
pub const KERNEL_VMA: u64 = 0xFFFF_FFFF_8000_0000;

/// 2 MiB.
const SIZE_2M: u64 = 2 * 1024 * 1024;
/// 1 GiB.
const SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Page-table entry: present.
const PTE_PRESENT: u64 = 1 << 0;
/// Page-table entry: writable.
const PTE_WRITE: u64 = 1 << 1;
/// Page-table entry: page size — this entry maps a large page, not a table.
const PTE_HUGE: u64 = 1 << 7;
/// Page-table entry: no-execute. Requires `EFER.NXE`, which
/// [`enable_no_execute`] sets before any of these tables are loaded.
const PTE_NX: u64 = 1 << 63;
/// The physical-address field of an entry.
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Rights for one mapping, kept separate from the raw bits so callers state
/// intent and this module owns the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights {
    /// Writable.
    pub write: bool,
    /// Executable.
    pub exec: bool,
}

impl Rights {
    /// Read-only, non-executable — rodata, and the default for anything whose
    /// purpose is unclear.
    pub const RO: Self = Self { write: false, exec: false };
    /// Read/write, non-executable — data, bss, the linear map.
    pub const RW: Self = Self { write: true, exec: false };
    /// Read/execute — text.
    pub const RX: Self = Self { write: false, exec: true };

    const fn bits(self) -> u64 {
        let mut b = PTE_PRESENT;
        if self.write {
            b |= PTE_WRITE;
        }
        if !self.exec {
            b |= PTE_NX;
        }
        b
    }
}

/// A four-level page-table tree under construction.
pub struct PageTables {
    /// Physical address of the PML4 — the value to load into `CR3`.
    pml4: u64,
    /// Whether the CPU supports 1 GiB pages.
    gib_pages: bool,
}

impl PageTables {
    /// Allocate an empty PML4 and probe for 1 GiB page support.
    ///
    /// # Errors
    /// Propagates an allocation failure.
    ///
    /// # Safety
    /// `bs` must be live boot services, and the machine identity-mapped.
    pub unsafe fn new(bs: &BootServices) -> Result<Self, Error> {
        // SAFETY: caller guarantees live boot services.
        let pml4 = unsafe { alloc_pages(bs, "allocate PML4", 1)? };
        Ok(Self { pml4, gib_pages: gib_pages_supported() })
    }

    /// The value to load into `CR3`.
    #[must_use]
    pub const fn cr3(&self) -> u64 {
        self.pml4
    }

    /// Whether 1 GiB pages will be used for the large maps.
    #[must_use]
    pub const fn uses_gib_pages(&self) -> bool {
        self.gib_pages
    }

    /// Map `size` bytes of physical memory at `phys` to virtual `virt`.
    ///
    /// Uses the largest page size that both alignments and `size` allow, down to
    /// 4 KiB. `virt`, `phys` and `size` must be 4 KiB aligned.
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
        bs: &BootServices,
        virt: u64,
        phys: u64,
        size: u64,
        rights: Rights,
    ) -> Result<(), Error> {
        if !virt.is_multiple_of(PAGE_SIZE)
            || !phys.is_multiple_of(PAGE_SIZE)
            || !size.is_multiple_of(PAGE_SIZE)
        {
            return Err(Error::own("misaligned mapping request"));
        }

        let mut off = 0u64;
        while off < size {
            let (v, p, left) = (virt + off, phys + off, size - off);
            let step = if self.gib_pages
                && v.is_multiple_of(SIZE_1G)
                && p.is_multiple_of(SIZE_1G)
                && left >= SIZE_1G
            {
                // SAFETY: caller's conditions; the entry is installed at PDPT
                // level, where PS=1 means a 1 GiB page.
                unsafe { self.map_huge(bs, v, p, rights, 2)? };
                SIZE_1G
            } else if v.is_multiple_of(SIZE_2M) && p.is_multiple_of(SIZE_2M) && left >= SIZE_2M {
                // SAFETY: as above, at PD level, where PS=1 means 2 MiB.
                unsafe { self.map_huge(bs, v, p, rights, 1)? };
                SIZE_2M
            } else {
                // SAFETY: as above.
                unsafe { self.map_4k(bs, v, p, rights)? };
                PAGE_SIZE
            };
            off += step;
        }
        Ok(())
    }

    /// Install a large-page entry at `stop_level` (2 = PDPT/1 GiB, 1 = PD/2 MiB).
    ///
    /// # Safety
    /// As [`Self::map`].
    unsafe fn map_huge(
        &mut self,
        bs: &BootServices,
        virt: u64,
        phys: u64,
        rights: Rights,
        stop_level: u32,
    ) -> Result<(), Error> {
        let mut table = self.pml4;
        let mut level = 3u32;
        while level > stop_level {
            // SAFETY: `table` is a page this loader allocated and zeroed.
            table = unsafe { next_table(bs, table, index(virt, level))? };
            level -= 1;
        }
        // SAFETY: `table` is a live table page; the index is in range by
        // construction of `index`.
        unsafe { write_entry(table, index(virt, level), phys | rights.bits() | PTE_HUGE) };
        Ok(())
    }

    /// Install a 4 KiB entry.
    ///
    /// # Safety
    /// As [`Self::map`].
    unsafe fn map_4k(
        &mut self,
        bs: &BootServices,
        virt: u64,
        phys: u64,
        rights: Rights,
    ) -> Result<(), Error> {
        let mut table = self.pml4;
        for level in (1..=3).rev() {
            // SAFETY: `table` is a page this loader allocated and zeroed.
            table = unsafe { next_table(bs, table, index(virt, level))? };
        }
        // SAFETY: `table` is the PT for this address.
        unsafe { write_entry(table, index(virt, 0), phys | rights.bits()) };
        Ok(())
    }
}

/// The index into the level-`level` table for `virt` (3 = PML4 … 0 = PT).
const fn index(virt: u64, level: u32) -> usize {
    ((virt >> (12 + 9 * level)) & 0x1FF) as usize
}

/// Write one entry.
///
/// # Safety
/// `table` must be a live, loader-owned table page and `idx < 512`.
unsafe fn write_entry(table: u64, idx: usize, value: u64) {
    // SAFETY: caller guarantees the table page and index.
    unsafe { (table as *mut u64).add(idx).write(value) };
}

/// Read one entry.
///
/// # Safety
/// As [`write_entry`].
unsafe fn read_entry(table: u64, idx: usize) -> u64 {
    // SAFETY: caller guarantees the table page and index.
    unsafe { (table as *const u64).add(idx).read() }
}

/// Follow `table[idx]` to the next level, allocating that level if absent.
///
/// Intermediate entries are deliberately permissive (present + writable, U/S
/// clear, NX clear): x86 takes the **AND** of the write bits and the **OR** of
/// the NX bits along the walk, so a restrictive intermediate would silently
/// override every leaf beneath it. Rights belong on the leaf, in one place.
///
/// # Safety
/// `bs` must be live and `table` a loader-owned table page.
unsafe fn next_table(bs: &BootServices, table: u64, idx: usize) -> Result<u64, Error> {
    // SAFETY: caller guarantees the table page.
    let entry = unsafe { read_entry(table, idx) };
    if entry & PTE_PRESENT != 0 {
        if entry & PTE_HUGE != 0 {
            // Two mappings of different granularity have collided. Splitting the
            // large page would be possible, but this loader never needs it, and
            // pretending to handle a case that cannot arise hides the day it does.
            return Err(Error::own("mapping collides with an existing large page"));
        }
        return Ok(entry & PTE_ADDR_MASK);
    }
    // SAFETY: caller guarantees live boot services.
    let page = unsafe { alloc_pages(bs, "allocate page table", 1)? };
    // SAFETY: caller guarantees the table page.
    unsafe { write_entry(table, idx, page | PTE_PRESENT | PTE_WRITE) };
    Ok(page)
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
/// Order matters: with NXE clear, every entry carrying [`PTE_NX`] is a *reserved
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
