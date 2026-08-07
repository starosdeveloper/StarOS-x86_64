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
