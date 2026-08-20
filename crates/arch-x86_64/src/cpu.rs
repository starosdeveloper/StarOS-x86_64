//! Core CPU control: masking interrupts and stopping.

use core::arch::asm;

/// Stop this core for good, with interrupts masked.
///
/// `cli` before `hlt`, and the loop around both: without masking, an interrupt
/// wakes the core and execution continues past a point the caller declared
/// unreachable; without the loop, a non-maskable interrupt does the same.
pub fn halt() -> ! {
    loop {
        // SAFETY: masking interrupts and halting affects only this core, and the
        // caller has decided it must stop.
        unsafe { asm!("cli; hlt", options(nomem, nostack, preserves_flags)) };
    }
}

/// Mask interrupts on this core (`cli`).
///
/// # Safety
/// Leaves the core unable to be preempted or to service devices. Every caller
/// must re-enable or hand off to code that does.
#[inline]
pub unsafe fn disable_interrupts() {
    // SAFETY: forwarded from this function's contract.
    unsafe { asm!("cli", options(nomem, nostack, preserves_flags)) };
}

/// Unmask interrupts on this core (`sti`).
///
/// # Safety
/// Only valid once an interrupt descriptor table is installed: an interrupt
/// arriving with no IDT is a triple fault and an instant reset, with no output.
#[inline]
pub unsafe fn enable_interrupts() {
    // SAFETY: forwarded from this function's contract.
    unsafe { asm!("sti", options(nomem, nostack, preserves_flags)) };
}

/// Sleep this core until an interrupt arrives, then return with interrupts
/// masked again.
///
/// `sti; hlt` is one instruction pair for a reason that is not style: `sti` does
/// not take effect until *after* the instruction that follows it, precisely so
/// that this sequence cannot lose a wakeup. Written as `sti` then a separate
/// `hlt`, an interrupt arriving in between would be serviced and the core would
/// then halt with nothing left to wake it — the classic idle-loop hang. The
/// architecture closes the window; splitting the pair reopens it.
///
/// The `cli` afterwards restores the mask, so a caller inside an interrupt-masked
/// critical section — which every scheduler idle loop is — comes back to the
/// state it was in.
///
/// # Safety
/// Only valid with an IDT installed and something able to raise an interrupt;
/// otherwise this halts forever. Unmasks interrupts for the duration, so the
/// caller's masked section is briefly open.
#[inline]
pub unsafe fn wait_for_interrupt() {
    // SAFETY: forwarded from this function's contract. `nostack` holds: neither
    // instruction touches memory.
    unsafe { asm!("sti; hlt; cli", options(nomem, nostack, preserves_flags)) };
}

/// Whether interrupts are currently unmasked, from `RFLAGS.IF` (bit 9).
#[must_use]
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    // SAFETY: pushing and popping RFLAGS reads processor state without changing
    // it. `nostack` is deliberately absent: this touches the stack.
    unsafe { asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags)) };
    flags & (1 << 9) != 0
}

/// The linear address that caused the most recent page fault, from `CR2`.
///
/// Read as early as possible in a `#PF` handler: `CR2` holds the *most recent*
/// faulting address, not the one belonging to any particular frame, so a second
/// page fault — including one taken by the reporting code itself — overwrites it.
#[must_use]
pub fn read_cr2() -> u64 {
    let cr2: u64;
    // SAFETY: reading a control register changes no state.
    unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags)) };
    cr2
}

/// Mask interrupts and report whether they were enabled before.
///
/// The pair with [`irq_restore`], and the reason it returns the previous state
/// rather than being a bare `cli`: a lock that unconditionally re-enables
/// interrupts on release would silently unmask them inside a caller that had
/// deliberately masked them, and that bug only shows up as an interrupt arriving
/// somewhere it was supposed to be impossible.
///
/// # Safety
/// Every caller must pair this with [`irq_restore`] on the same core.
#[must_use]
pub unsafe fn irq_save() -> bool {
    let was_enabled = interrupts_enabled();
    // SAFETY: forwarded; the caller restores.
    unsafe { disable_interrupts() };
    was_enabled
}

/// Restore the interrupt state [`irq_save`] reported.
///
/// # Safety
/// `was_enabled` must come from a matching [`irq_save`] on this core.
pub unsafe fn irq_restore(was_enabled: bool) {
    if was_enabled {
        // SAFETY: forwarded; interrupts were enabled before the matching save,
        // which means an IDT was already installed.
        unsafe { enable_interrupts() };
    }
}

/// The current page-table root, from `CR3`.
#[must_use]
pub fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading a control register changes no state.
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    cr3
}

/// Switch to the page-table tree rooted at `pml4`.
///
/// Takes effect on the *next* instruction, which is the whole difficulty: that
/// instruction, the stack under it and the code that returns from here must all
/// be mapped at the same virtual addresses in the new tree. Writing `CR3` also
/// flushes every non-global TLB entry, so no invalidation is needed afterwards.
///
/// # Safety
/// `pml4` must be the physical address of a valid four-level tree that maps the
/// caller's code, stack and every datum it touches before the next full barrier.
pub unsafe fn write_cr3(pml4: u64) {
    // SAFETY: forwarded from this function's contract.
    unsafe { asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags)) };
}

/// The current `CR4`.
#[must_use]
pub fn read_cr4() -> u64 {
    let cr4: u64;
    // SAFETY: reading a control register changes no state.
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
    cr4
}

/// `CR4.SMEP`: a supervisor instruction fetch from a user page faults.
pub const CR4_SMEP: u64 = 1 << 20;
/// `CR4.SMAP`: a supervisor data access to a user page faults unless `AC` is set.
pub const CR4_SMAP: u64 = 1 << 21;

/// Write `CR4`.
///
/// # Safety
/// The value must keep every feature the kernel currently depends on enabled;
/// clearing `PAE` or `PGE` here is not recoverable.
pub unsafe fn write_cr4(cr4: u64) {
    // SAFETY: forwarded from this function's contract.
    unsafe { asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags)) };
}

/// What the CPU says it can do, from the features this kernel cares about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Features {
    /// `SMEP`: leaf 7, sub-leaf 0, EBX bit 7.
    pub smep: bool,
    /// `SMAP`: leaf 7, sub-leaf 0, EBX bit 20.
    pub smap: bool,
    /// `PDPE1GB`: leaf 0x8000_0001, EDX bit 26.
    pub gib_pages: bool,
}

impl Features {
    /// Ask the CPU.
    ///
    /// Both leaves are checked for existence first. CPUID does not fail on an
    /// unsupported leaf — it returns the highest supported one instead, so a bit
    /// read from a leaf that does not exist is a bit read out of something else
    /// entirely, and it reads as "supported" about half the time.
    #[must_use]
    pub fn detect() -> Self {
        let basic_max = core::arch::x86_64::__cpuid(0).eax;
        let (smep, smap) = if basic_max >= 7 {
            let ebx = core::arch::x86_64::__cpuid_count(7, 0).ebx;
            (ebx & (1 << 7) != 0, ebx & (1 << 20) != 0)
        } else {
            (false, false)
        };
        let ext_max = core::arch::x86_64::__cpuid(0x8000_0000).eax;
        let gib_pages = ext_max >= 0x8000_0001
            && core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 26) != 0;
        Self { smep, smap, gib_pages }
    }
}

/// Allow supervisor access to user pages until [`clac`], by setting `EFLAGS.AC`.
///
/// This is the explicit hole in SMAP, and the point of SMAP is that the hole has
/// to be asked for: without it, a kernel that dereferences a user pointer by
/// mistake reads user memory happily, and with it that mistake faults. The same
/// bargain as `PAN` plus `at s1e0r` in the aarch64 tree.
///
/// # Safety
/// Only between here and a matching [`clac`], and only around an access the
/// caller has already validated. Nothing may fault or be preempted in between —
/// `AC` is part of `EFLAGS`, so an interrupt would carry it into the handler.
/// Neither of the two below carries `nomem`, and that omission is the whole
/// mechanism. `nomem` promises the compiler that an `asm!` block neither reads
/// nor writes memory, which makes it free to move memory accesses *across* the
/// block — and the only thing these two instructions do is decide whether the
/// accesses between them are allowed. At `opt-level = "z"` LLVM took that
/// permission and hoisted the copy in `usermode::read_user_msg` out of the window
/// entirely: the boot died in `--release` only, in ring 0, with `#PF at
/// 0x7ffffef8: supervisor read of a page it may not read` — the kernel reading a
/// user stack with SMAP on, which is exactly the mistake SMAP exists to catch,
/// arriving from the code that had asked for permission and been reordered out of
/// it. Without `nomem` the block is an optimisation barrier for memory, which is
/// what a window has to be.
#[inline]
pub unsafe fn stac() {
    // SAFETY: forwarded. `stac` is a trap-free instruction when SMAP is
    // supported, and the caller has established that it is.
    unsafe { asm!("stac", options(nostack)) };
}

/// Close the hole [`stac`] opened.
///
/// # Safety
/// Pairs with a preceding [`stac`] on this core.
#[inline]
pub unsafe fn clac() {
    // SAFETY: forwarded.
    unsafe { asm!("clac", options(nostack)) };
}

/// Drop the TLB entry for one page.
///
/// Needed after *any* change to a live mapping, including creating one where
/// there was none: the CPU is allowed to cache the absence of a translation, so
/// a page that has just become present may still fault without this.
///
/// # Safety
/// Ring 0. Invalidating a page the caller does not own is harmless but wasteful.
pub unsafe fn invlpg(virt: u64) {
    // SAFETY: forwarded. `invlpg` reads no memory through the operand; it only
    // uses the address to select a TLB entry.
    unsafe { asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)) };
}

/// Read a model-specific register.
///
/// The value arrives in two halves, `EDX:EAX`, which is why this is not simply a
/// 64-bit move: the instruction predates 64-bit registers and kept its shape.
///
/// # Safety
/// `msr` must exist on this CPU. Reading one that does not raises `#GP`, which
/// during bring-up is a fault report and after it is a dead core.
#[must_use]
pub unsafe fn read_msr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: forwarded from this function's contract.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high,
             options(nomem, nostack, preserves_flags));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Write a model-specific register.
///
/// # Safety
/// `msr` must exist and `value` must be legal for it. These registers control
/// paging modes, the syscall entry point and the local APIC's base address;
/// a wrong value is not a fault so much as a different machine.
pub unsafe fn write_msr(msr: u32, value: u64) {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32,
             options(nomem, nostack, preserves_flags));
    }
}
