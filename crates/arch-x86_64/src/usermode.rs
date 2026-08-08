//! Dropping from ring 0 to ring 3 (entering user mode).
//!
//! The counterpart of the aarch64 tree's `usermode::enter_el0`, and the same idea
//! reached a different way. AArch64 stages the target state in three system
//! registers — `ELR_EL1`, `SP_EL0`, `SPSR_EL1` — and `eret` consumes them. x86 has
//! no dedicated exception-return registers and no `eret`: the way down is `iretq`,
//! reading a five-word frame off the *current* stack.
//!
//! That frame is the whole interface, and its order is the order the CPU pushes
//! when it takes an interrupt from ring 3 — `SS`, `RSP`, `RFLAGS`, `CS`, `RIP`,
//! from the highest address down. Entering user mode is therefore literally
//! returning from an interrupt that never happened, which is why this needs no
//! instruction of its own.
//!
//! ## Two things the frame decides
//! **`CS` and `SS` must have RPL 3.** `iretq` compares the frame's `CS` privilege
//! against the current one and only *lowers* it; a frame naming ring 0 returns to
//! ring 0, silently, and the "user" program then runs with kernel privilege while
//! every log line still says it started. The selectors come from
//! [`crate::gdt`], where they carry their RPL, so this cannot be got wrong here
//! without being wrong there too — and the GDT's own host tests assert DPL 3 on
//! all three user descriptors.
//!
//! **`RFLAGS` decides whether user code can be preempted.** `IF` set is what lets
//! the timer take the CPU back from a ring-3 task; clear, and a user program with
//! an infinite loop owns the machine and there is nothing the kernel can do about
//! it, because the only way back in is a fault the program will not take.
//!
//! ## What must already be true
//! `TSS.rsp0` has to hold this task's kernel stack before the first ring-3
//! instruction runs, because an interrupt from ring 3 has the CPU switch stacks
//! *using that field* and it is not consulted anywhere else. Null there is a
//! `#DF` on the first timer tick. The scheduler sets it on every switch (see
//! `gdt::set_privilege_stack`), and this function does not, precisely so there is
//! one place that answers "which kernel stack does the running task use" rather
//! than two that can disagree.

use core::arch::asm;

/// `RFLAGS` for a task entering ring 3: bit 1 (always one) and `IF`.
///
/// Nothing else. In particular `DF` clear, because compiled code may assume it,
/// and `AC` clear, because `CR4.SMAP` is on and a user task has no business
/// inheriting a kernel flag.
const USER_RFLAGS: u64 = (1 << 1) | (1 << 9);

/// Drop to ring 3 and begin executing `entry` on stack `user_sp`. Never returns:
/// control comes back only through a syscall, an interrupt or a fault.
///
/// # Safety
/// `entry` must point at ring-3-executable code and `user_sp` at a ring-3-writable,
/// 16-byte-aligned stack top, both mapped `USER` in the live tree. The IDT must be
/// installed, `TSS.rsp0` must hold a kernel stack, and `syscall::init` must have
/// run — every one of those is a way back in, and a ring-3 task with no way back
/// in is a machine that has stopped.
pub unsafe fn enter_ring3(entry: u64, user_sp: u64) -> ! {
    // SAFETY: builds the exception-return frame the caller's contract describes
    // and consumes it. `iretq` does not return, hence `noreturn`.
    unsafe {
        asm!(
            "push {ss}",
            "push {sp}",
            "push {flags}",
            "push {cs}",
            "push {ip}",
            "iretq",
            ss = in(reg) u64::from(crate::gdt::USER_DATA),
            sp = in(reg) user_sp,
            flags = in(reg) USER_RFLAGS,
            cs = in(reg) u64::from(crate::gdt::USER_CODE),
            ip = in(reg) entry,
            options(noreturn),
        );
    }
}
