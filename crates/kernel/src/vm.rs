//! The kernel's own page tables, and the end of the loader's.
//!
//! Up to here the kernel has been living on a tree the loader built, which
//! contains one mapping it must not keep: the identity map of the low 4 GiB.
//! That mapping exists for exactly one instruction — the loader's `mov cr3`
//! takes effect on the *next* one, so the loader has to be mapped at the same
//! address in both trees. Once the kernel is running at `KERNEL_VMA`, nothing
//! needs it, and keeping it means physical address 0 stays readable and writable
//! from ring 0 forever. A null dereference in this kernel currently reads real
//! memory and returns. That is what this module ends.
//!
//! ## What the new tree has
//! * **Linear map** at [`PHYS_MAP_BASE`], covering all RAM and at least the low
//!   4 GiB, read/write and non-executable. This is how the kernel reaches
//!   physical memory: page tables, ACPI tables, the framebuffer, the frame pool.
//! * **The kernel image** at `KERNEL_VMA`, one *section* at a time — text
//!   read-execute, rodata read-only, data and bss read-write — which is finer
//!   than the loader's per-segment mapping and is why `linker.ld` aligns each
//!   section to a page.
//! * **The boot stack**, read/write, with its guard page still absent.
//!
//! and nothing else. No identity map, no user mappings, and no page at address
//! zero.
//!
//! ## Why it is checked before it is used
//! `mov cr3` is the least forgiving instruction in the kernel. If the next
//! instruction is not mapped, or the stack is not mapped, or the console is not
//! mapped, the result is a triple fault: no output, no fault report, and the IDT
//! installed in phase 1.3 never gets a chance. So the tree is *walked* first —
//! [`staros_paging::Mapper::translate`] resolves the addresses the switch depends
//! on and the rights they carry, and a mismatch stops the boot with a message
//! rather than resetting the machine.

use core::fmt::Write;

use staros_arch_x86_64::cpu::{self, Features};
use staros_bootinfo::{Framebuffer, PHYS_MAP_BASE};
use staros_paging::{FrameSource, MapError, Mapper, Rights, PAGE_SIZE, SIZE_1G};

use crate::console::Console;
use crate::mem;

/// The linear map always covers at least this much, whatever RAM there is.
///
/// The same floor the loader uses, for the same reason: the framebuffer and the
/// local APIC live in the hole above RAM and below 4 GiB, and both are reached
/// through the linear map. A map that stopped at the end of RAM would need a
/// second, special-cased mapping for each of them.
const MIN_LINEAR: u64 = 4 * SIZE_1G;

unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __bss_end: u8;
    static __stack_guard: u8;
    static __stack_bottom: u8;
    static __stack_top: u8;
}

/// Frames from the kernel's own pool, reached through the linear map.
struct KernelFrames;

// SAFETY: `alloc_frame` returns a page-aligned 4 KiB frame owned by nobody else
// (the pool hands each out once), which is zeroed here before being returned;
// `table` resolves it through the linear map, which covers all RAM in both the
// loader's tree and the one being built. Frames do not move, so a pointer stays
// valid across further allocations.
unsafe impl FrameSource for KernelFrames {
    fn alloc_table(&mut self) -> Option<u64> {
        let frame = mem::alloc_frame()?.0 as u64;
        let virt = staros_bootinfo::phys_to_virt(frame) as *mut u8;
        // The buddy allocator recycles frames without clearing them, and a page
        // table read as garbage is 512 entries pointing at arbitrary memory with
        // arbitrary rights.
        // SAFETY: the frame was just allocated exclusively and is mapped
        // read/write through the linear map.
        unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE as usize) };
        Some(frame)
    }

    fn table(&mut self, phys: u64) -> *mut u64 {
        staros_bootinfo::phys_to_virt(phys) as *mut u64
    }
}

/// What was built, for the boot log.
#[derive(Clone, Copy, Debug)]
pub struct Tables {
    /// Physical address of the new PML4.
    pub root: u64,
    /// How far the linear map reaches.
    pub linear_bytes: u64,
    /// Whether 1 GiB pages were used.
    pub gib_pages: bool,
    /// Whether `CR4.SMEP` is set, read back from the register.
    pub smep: bool,
    /// Whether `CR4.SMAP` is set, read back from the register.
    pub smap: bool,
}

/// Address of a linker symbol.
///
/// A macro rather than a function because `&raw const` on an extern static is
/// safe — it takes an address without reading anything — while passing the
/// static by reference is not.
macro_rules! sym {
    ($name:ident) => {
        (&raw const $name) as u64
    };
}

/// Map one section of the kernel image at the rights `linker.ld` gives it.
///
/// `from` and `to` are virtual; the physical address follows from where the
/// loader placed the image, because the image is contiguous by construction.
fn place(
    mapper: &mut Mapper<'_, KernelFrames>,
    kernel_phys: u64,
    from: u64,
    to: u64,
    rights: Rights,
) -> Result<(), &'static str> {
    if to <= from {
        return Ok(());
    }
    let phys = kernel_phys + (from - sym!(__text_start));
    mapper.map(from, phys, to - from, rights).map_err(MapError::as_str)
}

/// Build the kernel's tree, verify it, switch to it, and turn on SMEP/SMAP.
///
/// # Errors
/// Returns a message naming what could not be mapped or did not verify. Every
/// one of them ends the boot: continuing on the loader's tables would work, and
/// would mean shipping a kernel whose null pointers are valid.
///
/// # Safety
/// Called once, on the boot core, after [`mem::init`] and with interrupts still
/// masked. `kernel_phys` must be the physical base of this image as the hand-off
/// reports it.
pub unsafe fn init(
    console: &mut Console,
    kernel_phys: u64,
    highest_ram: u64,
    framebuffer: Option<Framebuffer>,
) -> Result<Tables, &'static str> {
    let features = Features::detect();
    let mut frames = KernelFrames;
    let mut mapper = Mapper::new(&mut frames, features.gib_pages).map_err(MapError::as_str)?;

    // The linear map, rounded up so its tail can still use a large page.
    let linear_bytes = highest_ram.max(MIN_LINEAR).next_multiple_of(SIZE_1G);
    mapper
        .map(PHYS_MAP_BASE, 0, linear_bytes, Rights::RW)
        .map_err(MapError::as_str)?;

    // The image, section by section, at the rights `linker.ld` declares for the
    // corresponding program headers. Finer than the loader's per-segment
    // mapping: rodata and data share one `PT_LOAD` there and get separate
    // treatment here.
    let m = &mut mapper;
    place(m, kernel_phys, sym!(__text_start), sym!(__text_end), Rights::RX)?;
    place(m, kernel_phys, sym!(__rodata_start), sym!(__rodata_end), Rights::RO)?;
    place(m, kernel_phys, sym!(__data_start), sym!(__bss_end), Rights::RW)?;
    // The stack, and deliberately *not* the guard page between it and `.bss`.
    place(m, kernel_phys, sym!(__stack_bottom), sym!(__stack_top), Rights::RW)?;

    // A framebuffer above the linear map's reach would otherwise be lost, and the
    // console is holding a reference into it right now.
    if let Some(fb) = framebuffer {
        let end = fb.phys.saturating_add(fb.bytes());
        if end > linear_bytes {
            let base = fb.phys & !(PAGE_SIZE - 1);
            let len = (end - base).next_multiple_of(PAGE_SIZE);
            mapper
                .map(PHYS_MAP_BASE + base, base, len, Rights::RW)
                .map_err(MapError::as_str)?;
        }
    }

    let root = mapper.root();
    verify(console, &mut mapper, framebuffer)?;

    // From here the loader's tables are gone, along with the identity map and
    // everything address zero used to reach.
    // SAFETY: `verify` has just resolved this instruction's page, the stack, the
    // console and the linear map in the tree being loaded, and found them mapped
    // with the rights this code needs.
    unsafe { cpu::write_cr3(root) };

    // After the switch, not before: SMAP makes a supervisor access to a *user*
    // page fault, and the loader's tables have no user pages at all, so enabling
    // it earlier would prove nothing and could only be undone by a fault.
    let mut cr4 = cpu::read_cr4();
    if features.smep {
        cr4 |= cpu::CR4_SMEP;
    }
    if features.smap {
        cr4 |= cpu::CR4_SMAP;
    }
    // SAFETY: only the two supervisor-protection bits are added; every feature
    // the kernel already depends on is preserved by starting from the current
    // value.
    unsafe { cpu::write_cr4(cr4) };

    // Read back rather than reporting what was intended. `CR4` bits for features
    // the CPU does not implement do not stick, and a boot log that says a
    // protection is on when it is not is worse than one that says nothing.
    let cr4 = cpu::read_cr4();
    Ok(Tables {
        root,
        linear_bytes,
        gib_pages: features.gib_pages,
        smep: cr4 & cpu::CR4_SMEP != 0,
        smap: cr4 & cpu::CR4_SMAP != 0,
    })
}

/// Walk the new tree and refuse to load it if anything the switch needs is wrong.
///
/// The checks are chosen by what a mistake costs. The first three are the ones
/// that turn into a triple fault; the rest are the ones that would boot happily
/// and be wrong — a writable text section, an executable stack, a mapping at
/// address zero.
fn verify(
    console: &mut Console,
    mapper: &mut Mapper<'_, KernelFrames>,
    framebuffer: Option<Framebuffer>,
) -> Result<(), &'static str> {
    // This function's own address: the page that has to survive `mov cr3`.
    let here = verify as *const () as u64;
    let stack = &here as *const u64 as u64;

    let text = mapper.translate(here).ok_or("the code doing the switch is not mapped")?;
    if !text.rights.exec {
        return Err("kernel text is mapped no-execute");
    }
    if text.rights.write {
        return Err("kernel text is mapped writable: W^X is not being enforced");
    }
    if mapper.translate(stack).is_none_or(|t| !t.rights.write) {
        return Err("the kernel stack is not mapped writable");
    }
    if mapper.translate(PHYS_MAP_BASE).is_none_or(|t| !t.rights.write) {
        return Err("the linear map is missing or read-only");
    }
    if let Some(fb) = framebuffer {
        let last = staros_bootinfo::phys_to_virt(fb.phys + fb.bytes() - 1);
        if mapper.translate(last).is_none_or(|t| !t.rights.write) {
            return Err("the framebuffer the console is drawing on is not mapped");
        }
    }

    // Rodata must not be executable and must not be writable — this is the half
    // of W^X that a per-segment mapping cannot express.
    let rodata = sym!(__rodata_start);
    if rodata < sym!(__rodata_end) {
        let t = mapper.translate(rodata).ok_or("kernel rodata is not mapped")?;
        if t.rights.write || t.rights.exec {
            return Err("kernel rodata is writable or executable");
        }
    }
    // Data must not be executable. `.bss` holds the IST stacks and the trap
    // frames land there; an executable stack is the oldest exploit in the book.
    let data = mapper.translate(sym!(__data_start)).ok_or("kernel data is not mapped")?;
    if data.rights.exec {
        return Err("kernel data is executable");
    }

    // And the two absences, which are the point of the exercise.
    if mapper.translate(0).is_some() {
        return Err("address zero is still mapped: a null dereference would not fault");
    }
    if mapper.translate(sym!(__stack_guard)).is_some() {
        return Err("the stack guard page is mapped: an overflow would not fault");
    }

    let _ = writeln!(
        console,
        "vm: verified - text {:#x} r-x, rodata r--, data rw-, 0x0 and the guard page absent",
        here,
    );
    Ok(())
}

/// A user address nothing else uses, for the SMAP self-test.
const SMAP_TEST_ADDR: u64 = 0x0000_0000_1000_0000;

/// Dereference address zero, which is now nobody's memory.
///
/// This is the criterion `docs/ROADMAP.md` set for phase 1.3 and could not meet
/// there: until this module ran, the low 4 GiB were identity-mapped by the
/// loader and address zero was ordinary RAM. A null dereference read it and
/// returned, which is the worst of both worlds — no fault, and a value.
pub fn selftest_null(console: &mut Console) -> bool {
    let _ = writeln!(console, "vm self-test: reading address 0x0");
    let slot = crate::traps::arm_page_fault(0);
    // SAFETY: the IDT is installed, the handler is armed to resume at `*slot`
    // for a fault at address zero, and this tree deliberately does not map it.
    unsafe { staros_arch_x86_64::selftest::read_unmapped(0, slot) };
    let taken = crate::traps::fault_was_taken();
    crate::traps::disarm();
    if !taken {
        let _ = writeln!(console, "vm SELF-TEST FAILED: reading 0x0 did not fault");
    }
    taken
}

/// Prove SMAP is on: map a user page, write to it from ring 0, and check that
/// the write faulted *and did not happen*.
///
/// The second half is the part that matters. A SMAP that was never enabled
/// produces no fault, no message and a successful store — the failure looks
/// exactly like success from the log alone. So the page is read back through the
/// hole [`cpu::stac`] opens, and the value that must still be there is the one
/// written before the test.
pub fn selftest_smap(console: &mut Console, tables: &Tables) -> bool {
    if !tables.smap {
        // Not a failure: a CPU without SMAP is a CPU without SMAP. The boot log
        // has already said so on the `vm:` line, which is the honest place for it.
        let _ = writeln!(console, "smap: not supported by this CPU, self-test skipped");
        return true;
    }
    let Some(frame) = mem::alloc_frame() else {
        let _ = writeln!(console, "smap SELF-TEST FAILED: no frame for the self-test page");
        return false;
    };
    let frame = frame.0 as u64;
    const SENTINEL: u64 = 0xC0FF_EE00_1234_5678;
    const INTRUDER: u64 = 0xDEAD_BEEF_DEAD_BEEF;

    // Seed the page through the linear map, which is a *kernel* mapping of the
    // same frame and therefore not subject to SMAP at all.
    let linear = staros_bootinfo::phys_to_virt(frame) as *mut u64;
    // SAFETY: the frame was just allocated exclusively and the linear map covers
    // all RAM read/write.
    unsafe { linear.write_volatile(SENTINEL) };

    let mut frames = KernelFrames;
    let mut mapper = Mapper::adopt(tables.root, &mut frames, tables.gib_pages);
    if let Err(e) = mapper.map(SMAP_TEST_ADDR, frame, PAGE_SIZE, Rights::RW.to_user()) {
        let _ = writeln!(console, "smap SELF-TEST FAILED: could not map the page: {}", e.as_str());
        mem::free_frame(staros_mm::PhysAddr(frame as usize));
        return false;
    }
    // The tree is live, and the CPU may have cached the *absence* of this
    // translation just as readily as a translation itself.
    // SAFETY: ring 0; the address was just given a mapping.
    unsafe { cpu::invlpg(SMAP_TEST_ADDR) };

    let _ = writeln!(
        console,
        "vm self-test: writing to the user page at {SMAP_TEST_ADDR:#x} from ring 0"
    );
    let slot = crate::traps::arm_page_fault(SMAP_TEST_ADDR);
    // SAFETY: the handler is armed to resume past this store; if SMAP is on, the
    // store faults and never happens, which is what is checked next.
    unsafe { staros_arch_x86_64::selftest::write_at(SMAP_TEST_ADDR, INTRUDER, slot) };
    let faulted = crate::traps::fault_was_taken();
    crate::traps::disarm();

    // SAFETY: the linear map is a kernel mapping, so this read is unaffected by
    // SMAP and shows what the store above actually did.
    let value = unsafe { linear.read_volatile() };
    let mut passed = true;
    match (faulted, value) {
        (true, SENTINEL) => {
            let _ = writeln!(console, "smap: the write faulted and did not happen");
        }
        (false, _) => {
            let _ = writeln!(console, "smap SELF-TEST FAILED: the write did not fault");
            passed = false;
        }
        (true, _) => {
            let _ = writeln!(console, "smap SELF-TEST FAILED: it faulted but the store landed anyway");
            passed = false;
        }
    }

    // And the sanctioned way through: `stac` is the explicit hole, and it has to
    // work, or every future copy to and from user space is broken.
    // SAFETY: SMAP is supported and enabled; the page is mapped writable, the
    // access is a single aligned store, and nothing between `stac` and `clac`
    // can fault or be preempted.
    let allowed = unsafe {
        cpu::stac();
        (SMAP_TEST_ADDR as *mut u64).write_volatile(INTRUDER);
        cpu::clac();
        linear.read_volatile()
    };
    if allowed == INTRUDER {
        let _ = writeln!(console, "smap: stac opened the hole, the same write succeeded");
    } else {
        let _ = writeln!(console, "smap SELF-TEST FAILED: stac did not permit the write");
        passed = false;
    }

    // Put it back. Leaving a user-accessible mapping behind would be a hole in
    // the address space nothing owns, and the frame belongs to the pool.
    mapper.unmap(SMAP_TEST_ADDR);
    // SAFETY: ring 0; the mapping was just removed and the TLB must forget it.
    unsafe { cpu::invlpg(SMAP_TEST_ADDR) };
    mem::free_frame(staros_mm::PhysAddr(frame as usize));
    passed
}
