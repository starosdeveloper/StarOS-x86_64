//! Deliberate faults, for proving the trap path works.
//!
//! Every other subsystem in this tree can be checked by reading what it printed.
//! An IDT cannot: an IDT that is subtly wrong produces *no* output, because the
//! failure mode of interrupt delivery is a triple fault and a reset. The only
//! evidence that the table is right is a fault that was caught, so the boot takes
//! three on purpose.
//!
//! They are ordered by how much they destroy:
//!
//! 1. [`breakpoint`] — `int3`, vector 3, no error code. Resumes by itself,
//!    because the CPU already advanced `RIP` past the instruction.
//! 2. [`read_unmapped`] — a read of an address nothing maps, vector 14, *with*
//!    an error code, resumed by the handler rewriting `RIP`. This is the pair
//!    that proves the error-code-or-dummy-push logic: if the two were swapped,
//!    one of them would report the wrong vector.
//! 3. [`overflow_the_stack`] — walks `RSP` down until it hits the guard page.
//!    Terminal, and last for that reason.
//!
//! All three are phase-1.3 scaffolding and come out when there is something else
//! for the kernel to do after booting.

use core::arch::asm;

/// Execute `int3`.
///
/// The handler may return without doing anything: the trap frame's `RIP` already
/// points at the following instruction.
pub fn breakpoint() {
    // SAFETY: a breakpoint with an IDT installed is an ordinary trap; without
    // one it is a triple fault, which is what the caller is testing for.
    unsafe { asm!("int3", options(nomem, nostack)) };
}

/// Read `address`, and continue at the instruction after the load.
///
/// The caller picks the address, because "unmapped" is a property of the page
/// tables in force and not of any particular constant. Address zero in
/// particular is *not* unmapped in this kernel today: the loader identity-maps
/// the low 4 GiB, so a null dereference reads real memory and returns. Phase 1.4
/// is what changes that.
///
/// `resume` is written, before the fault, with the address the handler must put
/// into `TrapFrame::rip` to step over the load. It has to be captured here rather
/// than computed by the handler, because only this code knows where the load
/// ends — the length of an x86 instruction is not something a fault report can
/// work out from the outside.
///
/// # Safety
/// An IDT must be installed and its handler must resume at `*resume` when it
/// sees a page fault at `address`. Without that, this never returns.
pub unsafe fn read_unmapped(address: u64, resume: *mut u64) {
    // SAFETY: forwarded. `resume` is a valid `*mut u64` supplied by the caller;
    // the fault is the point of the function.
    unsafe {
        asm!(
            "lea {tmp}, [rip + 2f]",
            "mov qword ptr [{slot}], {tmp}",
            // The fault. Everything after this executes only if the handler
            // resumed at the label below.
            "mov {tmp}, [{addr}]",
            "2:",
            tmp = out(reg) _,
            slot = in(reg) resume,
            addr = in(reg) address,
        );
    }
}

/// March the stack pointer downwards until it leaves the mapped stack.
///
/// Not recursion: an infinite recursion is something the optimiser is allowed to
/// reason about, and a tail call would turn it into a loop that never touches new
/// memory. This writes one word every 256 bytes, so it cannot skip over the 4 KiB
/// guard page, and it reaches it in 256 iterations from a 64 KiB stack.
///
/// What follows is two faults, not one. The write hits the unmapped guard page
/// and raises `#PF`; delivering that `#PF` means pushing a frame, and `RSP` is
/// still inside the guard page, so the push faults too. A fault while delivering
/// a fault is `#DF` — which is delivered on its own IST stack and therefore has
/// somewhere to push. Without the IST the third attempt fails and the CPU resets.
///
/// # Safety
/// Destroys the current stack. Never returns, whatever the handler does.
pub unsafe fn overflow_the_stack() -> ! {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        asm!(
            "2:",
            "sub rsp, 256",
            "mov qword ptr [rsp], 0",
            "jmp 2b",
            options(noreturn),
        );
    }
}

/// Write `value` to `address`, and continue at the instruction after the store.
///
/// The counterpart of [`read_unmapped`] for the faults a *read* cannot provoke:
/// a store to a read-only page, and a supervisor store to a user page with SMAP
/// on. Whether the store actually happened is the caller's check, and it is the
/// important one — a SMAP that is not enabled produces no fault and no message,
/// just a successful write.
///
/// # Safety
/// An IDT must be installed and its handler must resume at `*resume` when it
/// sees a page fault at `address`. If the store does not fault, it takes effect.
pub unsafe fn write_at(address: u64, value: u64, resume: *mut u64) {
    // SAFETY: forwarded from this function's contract.
    unsafe {
        asm!(
            "lea {tmp}, [rip + 2f]",
            "mov qword ptr [{slot}], {tmp}",
            "mov qword ptr [{addr}], {val}",
            "2:",
            tmp = out(reg) _,
            slot = in(reg) resume,
            addr = in(reg) address,
            val = in(reg) value,
        );
    }
}
