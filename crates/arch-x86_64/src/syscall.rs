//! The `syscall`/`sysret` path: how ring 3 gets into this kernel and back out.
//!
//! The counterpart of the aarch64 tree's `svc` handling, and the place where the
//! two architectures differ most. On AArch64 `svc` is an exception: it goes
//! through the same vector table as every other trap, the hardware switches to
//! `SP_EL1` on its own, and the return address and flags land in system registers
//! the kernel can read at leisure. None of that is true here.
//!
//! `syscall` is not an exception. It is a jump, and a remarkably bare one:
//!
//! - it loads `RIP` from [`IA32_LSTAR`] and `CS`/`SS` from [`IA32_STAR`];
//! - it puts the return address in `RCX` and the caller's `RFLAGS` in `R11`,
//!   **destroying whatever those held** — which is why the fourth syscall
//!   argument is `R10` and not `RCX` (see `docs/SPEC.md` §6);
//! - it clears whichever `RFLAGS` bits [`IA32_FMASK`] names;
//! - and it does **nothing at all** to `RSP`.
//!
//! That last one is the whole shape of this module. x86 has no `SP_EL0`/`SP_EL1`
//! pair: after `syscall` the kernel is executing with ring-3 privilege gone and
//! the ring-3 *stack* still in `RSP`. Touching memory before fixing that would
//! mean the kernel writing to a stack user space controls — and worse, one it can
//! unmap. So the first two instructions of the entry stub swap in a kernel stack,
//! and they need a scratch register to do it without pushing anything, which is
//! what `swapgs` and the [`PerCpu`] block exist for.
//!
//! ## `swapgs`, stated plainly
//! `swapgs` exchanges `IA32_GS_BASE` with [`IA32_KERNEL_GS_BASE`]. This kernel
//! keeps the arrangement as simple as it can be while still being correct:
//!
//! | | `GS_BASE` | `KERNEL_GS_BASE` |
//! |---|---|---|
//! | ring 3, and ring 0 outside this path | 0 | `&PERCPU` |
//! | inside the syscall stub | `&PERCPU` | 0 |
//!
//! So the stub swaps on the way in and back on the way out, and **nothing else in
//! the kernel touches `GS`** — including the interrupt stubs, which is why they do
//! not swap either. An interrupt taken from ring 3 gets its kernel stack from
//! `TSS.rsp0` (the CPU does that itself) and never reads `GS`, so there is nothing
//! to swap for. That stops being true the moment per-core state is reached through
//! `GS` in phase 4, and the interrupt path will need `swapgs` guarded by the
//! frame's `CS` at that point.
//!
//! ## The two ways back
//! `sysretq` is the fast one and the one with a trap in it. It takes `RIP` from
//! `RCX` — and if `RCX` is **non-canonical**, the `#GP` it raises is delivered
//! *before* the privilege change, in **ring 0**, on the kernel stack, with the
//! kernel's own `CS`. That is a privilege escalation primitive, not an
//! inconvenience: it hands ring 3 a fault in ring 0 at an address of its choosing.
//! So [`is_canonical`] is checked on the way out, and a return address that fails
//! it goes back through `iretq` instead — which handles any `RIP` and delivers the
//! resulting `#GP` in ring 3, where it belongs, killing the task that caused it.
//!
//! ## What `IA32_FMASK` has to clear
//! `IF`, or an interrupt arrives between `syscall` and the stack switch and the
//! CPU pushes a trap frame onto the user's stack. `TF`, or a debugger that
//! single-stepped into `syscall` single-steps the kernel. `AC`, or ring 3 sets it
//! and `SMAP` — the whole reason phase 1.4 turned it on — stops applying to the
//! kernel for the duration of the call. `DF`, `NT` and `RF` follow the same
//! argument: each is a flag the caller controls that changes how kernel code
//! behaves.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Extended Feature Enable Register. Bit 0 is what makes `syscall` an
/// instruction rather than `#UD`.
pub const IA32_EFER: u32 = 0xC000_0080;
/// `SYSCALL` enable, in [`IA32_EFER`].
pub const EFER_SCE: u64 = 1 << 0;

/// Segment selector bases for `syscall` and `sysret`. See [`star_value`].
pub const IA32_STAR: u32 = 0xC000_0081;
/// Where `syscall` jumps.
pub const IA32_LSTAR: u32 = 0xC000_0082;
/// Which `RFLAGS` bits `syscall` clears. See [`FMASK`].
pub const IA32_FMASK: u32 = 0xC000_0084;
/// The current `GS` base.
pub const IA32_GS_BASE: u32 = 0xC000_0101;
/// The `GS` base `swapgs` exchanges with [`IA32_GS_BASE`].
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Trap flag: single-step. Cleared, or a user debugger steps the kernel.
const RFLAGS_TF: u64 = 1 << 8;
/// Interrupt enable. Cleared, or an interrupt lands on the user stack.
const RFLAGS_IF: u64 = 1 << 9;
/// Direction flag. Cleared, because compiled code may assume it is.
const RFLAGS_DF: u64 = 1 << 10;
/// Nested task. Meaningless in long mode, and cleared so an `iret` cannot be
/// steered by it.
const RFLAGS_NT: u64 = 1 << 14;
/// Resume flag: suppresses instruction breakpoints for one instruction.
const RFLAGS_RF: u64 = 1 << 16;
/// Alignment check — and, when `CR4.SMAP` is set, the bit that *disables* SMAP.
/// Cleared, or ring 3 turns off the protection ring 0 relies on.
const RFLAGS_AC: u64 = 1 << 18;

/// The value written to [`IA32_FMASK`]: every flag the caller must not be able to
/// impose on the kernel.
pub const FMASK: u64 = RFLAGS_TF | RFLAGS_IF | RFLAGS_DF | RFLAGS_NT | RFLAGS_RF | RFLAGS_AC;

/// Build the [`IA32_STAR`] value from the two selector bases.
///
/// `IA32_STAR` does not hold four selectors; it holds two **bases**, and the
/// hardware derives the rest by adding fixed offsets:
///
/// - `syscall`: `CS = kernel_base`, `SS = kernel_base + 8`
/// - `sysretq`: `CS = user_base + 16`, `SS = user_base + 8` (both with RPL 3)
///
/// Which is why the GDT this kernel builds is laid out the way it is: kernel data
/// immediately after kernel code, and the user entries in the order "32-bit code,
/// data, 64-bit code" with no gaps. Getting the bases wrong does not fail to
/// build, does not fault at boot, and does not fail until the first return to
/// ring 3 — where it loads a plausible, wrong selector. So the derivation is a
/// function, and the host tests below check it against the actual GDT constants.
#[must_use]
pub const fn star_value(kernel_base: u16, user_base: u16) -> u64 {
    ((user_base as u64) << 48) | ((kernel_base as u64) << 32)
}

/// The `CS` `syscall` will load, given a [`star_value`].
#[must_use]
pub const fn syscall_cs(star: u64) -> u16 {
    ((star >> 32) & 0xFFFF) as u16
}

/// The `SS` `syscall` will load.
#[must_use]
pub const fn syscall_ss(star: u64) -> u16 {
    syscall_cs(star).wrapping_add(8)
}

/// The `CS` `sysretq` will load, RPL included — the hardware forces ring 3.
#[must_use]
pub const fn sysret_cs(star: u64) -> u16 {
    ((((star >> 48) & 0xFFFF) as u16).wrapping_add(16)) | 3
}

/// The `SS` `sysretq` will load, RPL included.
#[must_use]
pub const fn sysret_ss(star: u64) -> u16 {
    ((((star >> 48) & 0xFFFF) as u16).wrapping_add(8)) | 3
}

/// Whether `address` is canonical: bits 63:47 all equal.
///
/// The check `sysretq` does not do for you. A 64-bit address is only architecturally
/// valid if the top seventeen bits are a sign extension of bit 47; anything else is
/// a `#GP` when loaded into `RIP`, and in `sysretq`'s case a `#GP` taken *before*
/// the drop to ring 3.
///
/// Written as a sign-extending round trip rather than as a bit comparison because
/// that is what the architecture says the rule is, and because the arithmetic
/// shift makes both halves of the address space one case instead of two.
#[must_use]
pub const fn is_canonical(address: u64) -> bool {
    (((address << 16) as i64) >> 16) as u64 == address
}

/// Per-core state the syscall stub reaches through `GS`.
///
/// Two words, and both are load bearing at the exact moment there is no stack to
/// put anything on: [`PerCpu::kernel_rsp`] is where the kernel stack is, and
/// [`PerCpu::scratch_rsp`] is somewhere to leave the user's `RSP` that is not a
/// register (every register at that instant still belongs to the caller).
#[repr(C)]
pub struct PerCpu {
    /// Top of the kernel stack for whatever task is running. Written by the
    /// scheduler on every switch, read by the stub on every syscall.
    pub kernel_rsp: u64,
    /// Where the stub parks the user's `RSP` for the two instructions between
    /// "we are in the kernel" and "we are on a kernel stack".
    pub scratch_rsp: u64,
    /// This core's index into [`PERCPU`], and the number the kernel calls it by.
    ///
    /// Kept *here* rather than derived from the APIC id at each use. The APIC id
    /// is what hardware calls a core and is not an index — firmware leaves gaps —
    /// so anything that wanted an index would have to search a table it does not
    /// have, at a moment (the syscall path, a trap) where there is nothing to
    /// search with. `GS` already points here, so this is one load.
    pub cpu_index: u64,
}

/// Byte offsets into [`PerCpu`], shared with the assembly below as `const`
/// operands so the two cannot drift.
const OFF_KERNEL_RSP: usize = 0;
const OFF_SCRATCH_RSP: usize = 8;

/// How many cores this kernel can run on.
///
/// A fixed array rather than a heap allocation, because the syscall stub reaches
/// its own entry through `GS` with no chance to check anything: whatever this
/// points at has to exist before the first core is woken and never move.
pub const MAX_CPUS: usize = 32;

/// One [`PerCpu`] per core, each pointed at by that core's
/// [`IA32_KERNEL_GS_BASE`].
///
/// It was a single static while the kernel ran one core, on the argument that an
/// array indexed by a core id nothing could compute would be a promise rather
/// than a mechanism. Phase 4 is where the id becomes computable, so the array is
/// the mechanism now — and the index lives in the block itself, so a core can
/// answer "which am I" from the same pointer it already has.
static mut PERCPU: [PerCpu; MAX_CPUS] =
    [const { PerCpu { kernel_rsp: 0, scratch_rsp: 0, cpu_index: 0 } }; MAX_CPUS];

/// Tell the syscall path which kernel stack to switch to, for **this** core.
///
/// Called by the scheduler on every switch, because the answer is per-task: the
/// stack a syscall from ring 3 must land on is the kernel stack of the task that
/// made it, and no other.
///
/// `rsp` is the **top** — the first address the stub will push below.
pub fn set_kernel_stack(rsp: u64) {
    let index = cpu_index() as usize;
    let percpu = &raw mut PERCPU;
    // SAFETY: `PERCPU` is private to this module and `index` is this core's own
    // slot, which no other core writes. The stub's scratch word is untouched, and
    // the stub cannot run concurrently on this core.
    unsafe { (*percpu)[index].kernel_rsp = rsp };
}

/// The kernel stack the syscall path would switch to on this core, read back from
/// the block the hardware will actually use.
#[must_use]
pub fn kernel_stack() -> u64 {
    let index = cpu_index() as usize;
    let percpu = &raw const PERCPU;
    // SAFETY: as `set_kernel_stack`; a plain read of this core's own slot.
    unsafe { (*percpu)[index].kernel_rsp }
}

/// Which core this is, as an index into [`PERCPU`].
///
/// Read through `IA32_KERNEL_GS_BASE` rather than through `GS` itself, because
/// ordinary ring-0 code runs with `GS_BASE` zero — the block is in the *other*
/// base until `swapgs` brings it in, and this must answer correctly from both
/// sides of that swap.
#[must_use]
pub fn cpu_index() -> u64 {
    // SAFETY: ring 0. The MSR holds the address of this core's `PerCpu`, written
    // by `init` before any code that calls this can run.
    let block = unsafe { crate::cpu::read_msr(IA32_KERNEL_GS_BASE) } as *const PerCpu;
    if block.is_null() {
        return 0;
    }
    // SAFETY: the pointer is one this module installed, into a static that
    // outlives every core.
    unsafe { (*block).cpu_index }
}

/// The caller's state as the entry stub saves it, in push order.
///
/// `RAX` is both the syscall number on the way in and the result on the way out.
/// `RCX` and `R11` are not really "saved" — the instruction has already put the
/// return address and flags there, destroying whatever the caller had — so they
/// are named for what they now mean.
///
/// Everything the System V syscall convention says is preserved across a call is
/// here or is callee-saved; `RBX`, `RBP` and `R12`–`R15` are absent because the
/// Rust dispatcher preserves them for us, which is the same reason
/// [`crate::context::CpuContext`] holds exactly those six.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallFrame {
    /// Syscall number in, result out.
    pub rax: u64,
    /// First argument.
    pub rdi: u64,
    /// Second argument.
    pub rsi: u64,
    /// Third argument.
    pub rdx: u64,
    /// Fourth argument — `R10`, not `RCX`, because `syscall` overwrote `RCX`.
    pub r10: u64,
    /// Fifth argument.
    pub r8: u64,
    /// Sixth argument.
    pub r9: u64,
    /// Where ring 3 resumes. Arrived in `RCX`.
    pub rip: u64,
    /// The caller's `RFLAGS`, minus whatever [`FMASK`] cleared. Arrived in `R11`.
    pub rflags: u64,
    /// The caller's `RSP`, which `syscall` did not touch.
    pub user_rsp: u64,
}

/// How the entry stub should return to ring 3.
///
/// Not a style choice per call: [`Return::Iret`] is what a non-canonical
/// [`SyscallFrame::rip`] requires, and taking the fast path anyway is the
/// escalation this module exists to prevent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum Return {
    /// `sysretq`. Valid only when [`SyscallFrame::rip`] is canonical.
    Sysret = 0,
    /// `iretq`. Slower, and correct for any `RIP`.
    Iret = 1,
}

/// Signature of the kernel-side syscall handler.
///
/// It is handed the whole frame and may rewrite any of it — the result in `rax`,
/// and in principle where the caller resumes.
pub type Handler = fn(&mut SyscallFrame);

/// The installed handler, as a raw function pointer. Zero means none.
static HANDLER: AtomicUsize = AtomicUsize::new(0);

/// How many returns took the `iretq` path because `sysretq` was unsafe.
///
/// Counted because the hazard itself **cannot be reproduced on this test bench**,
/// and the mitigation would otherwise be unfalsifiable.
///
/// The non-canonical `sysret` check is an *Intel* behaviour: Intel silicon raises
/// `#GP` inside `sysretq` itself, before the privilege change, in ring 0. AMD
/// silicon does not check — the address goes into `RIP` and the fault happens on
/// the instruction fetch, in ring 3, which is harmless. QEMU's TCG interpreter
/// follows the AMD behaviour whatever CPU model is selected, so deleting the
/// check from this kernel and booting produces an *identical* log: a `#GP` in
/// ring 3, the task killed, every assertion green.
///
/// A mitigation that cannot be observed to be doing anything is a mitigation
/// nobody will notice the removal of. So the *choice* is counted rather than its
/// consequence: the boot asserts that one return went out through `iretq`, which
/// is false the moment the check is removed, on any machine.
static IRET_RETURNS: AtomicUsize = AtomicUsize::new(0);

/// How many returns to ring 3 have gone out through `iretq` rather than
/// `sysretq`. See [`IRET_RETURNS`].
#[must_use]
pub fn iret_returns() -> usize {
    IRET_RETURNS.load(Ordering::Relaxed)
}

/// Install the function every syscall is reported to.
pub fn set_handler(handler: Handler) {
    HANDLER.store(handler as usize, Ordering::SeqCst);
}

/// Called from the entry stub. Returns which instruction should take us back.
///
/// The canonical check happens **here**, after the handler, and deliberately not
/// before it: the handler is allowed to change where the caller resumes, so the
/// only value worth checking is the one that is actually about to be loaded.
///
/// # Safety
/// Called only by the assembly below, with `frame` pointing at the
/// [`SyscallFrame`] it just built on the kernel stack.
#[cfg(not(test))]
#[no_mangle]
unsafe extern "C" fn staros_syscall_dispatch(frame: *mut SyscallFrame) -> u64 {
    let handler = HANDLER.load(Ordering::SeqCst);
    if handler == 0 {
        // Ring 3 exists but nothing registered a handler. There is no sensible
        // answer and returning would run user code that thinks it was served.
        crate::cpu::halt()
    }
    // SAFETY: `handler` was stored from a `Handler` fn item by `set_handler` and
    // from nowhere else, so the transmute reverses exactly the cast.
    let handler: Handler = unsafe { core::mem::transmute::<usize, Handler>(handler) };
    // SAFETY: the caller guarantees the pointer is the live frame, and nothing
    // else holds a reference to it while this runs.
    let frame = unsafe { &mut *frame };
    handler(frame);

    if is_canonical(frame.rip) {
        Return::Sysret as u64
    } else {
        IRET_RETURNS.fetch_add(1, Ordering::Relaxed);
        Return::Iret as u64
    }
}

/// Turn on `syscall` and point it here.
///
/// # Safety
/// Called once per core, in ring 0, after [`crate::gdt::install`] — the selectors
/// written into `IA32_STAR` name descriptors that must already exist — and before
/// anything enters ring 3.
#[cfg(not(test))]
pub unsafe fn init(cpu: usize) {
    use crate::cpu;
    use crate::gdt;

    let star = star_value(gdt::KERNEL_CODE, gdt::USER_CODE32 & !3);
    let index = core::cmp::min(cpu, MAX_CPUS - 1);
    let percpu = &raw mut PERCPU;
    // SAFETY: this core's own slot, written before the block is published to the
    // MSR below, so nothing can read it half-initialised.
    unsafe { (*percpu)[index].cpu_index = index as u64 };
    // SAFETY: `PERCPU` is a static this module owns; taking the address of one
    // element does not read it, and `index` was clamped above.
    let percpu = unsafe { core::ptr::addr_of_mut!((*percpu)[index]) };

    // SAFETY: ring 0. Each write either enables an instruction that is currently
    // `#UD` or configures where it lands, and all four are in place before the
    // first ring-3 instruction runs.
    unsafe {
        cpu::write_msr(IA32_STAR, star);
        cpu::write_msr(IA32_LSTAR, staros_syscall_entry as *const () as u64);
        cpu::write_msr(IA32_FMASK, FMASK);
        // `GS` in ring 3 and in ordinary ring-0 code is zero; the per-core block
        // lives in the *other* base until `swapgs` brings it in. Written in this
        // order because writing the `GS` selector — which `gdt::install` does —
        // zeroes `IA32_GS_BASE`, so this must come after it and not before.
        cpu::write_msr(IA32_GS_BASE, 0);
        cpu::write_msr(IA32_KERNEL_GS_BASE, percpu as u64);
        // Last: until this bit is set `syscall` is an invalid opcode, and until
        // the four above are set it would jump somewhere arbitrary. Enabling the
        // instruction after configuring it is the difference between a boot and a
        // fault with no explanation.
        let efer = cpu::read_msr(IA32_EFER);
        cpu::write_msr(IA32_EFER, efer | EFER_SCE);
    }
}

/// Exchange `IA32_GS_BASE` with [`IA32_KERNEL_GS_BASE`] — a bare `swapgs`.
///
/// Exported because the `GS` arrangement this module documents is **per core, not
/// per task**, and the entry stub alone cannot maintain it.
///
/// The stub swaps once on the way in and once on the way out, which balances for
/// any syscall that returns. A handler that switches tasks in the middle — a
/// `Yield`, or an `Exit` that never comes back at all — leaves the core running
/// somebody else's code with `GS_BASE` still pointing at [`PerCpu`]. Nothing in
/// ring 0 reads `GS`, so that looks harmless; it is not. The *next* `syscall`,
/// from whichever task, swaps again and gets the user's base instead of the
/// kernel's — and the very next instruction writes through it. What that produces
/// is a `#PF` inside the entry stub, on the user's stack, at an address that
/// makes no sense, three tasks after the mistake.
///
/// So a handler that will not return promptly calls this before it switches, and
/// again afterwards if it comes back. Two instructions, and the invariant becomes
/// true of every point at which a task can be switched away from.
///
/// # Safety
/// Must be called in ring 0, and must be **paired**: each call inverts the state,
/// so an odd number of them leaves the core in exactly the condition described
/// above.
#[cfg(not(test))]
pub unsafe fn swap_gs() {
    // SAFETY: forwarded from this function's contract. `swapgs` touches only the
    // two MSRs and no memory.
    unsafe { core::arch::asm!("swapgs", options(nomem, nostack, preserves_flags)) };
}

/// Whether `syscall` is enabled, read back from `IA32_EFER`.
///
/// Read back rather than assumed: every value [`init`] writes is write-mostly,
/// and a machine that silently declined the enable would present as ring 3
/// dying on `#UD` with no other clue.
///
/// # Safety
/// Ring 0.
#[cfg(not(test))]
#[must_use]
pub unsafe fn is_enabled() -> bool {
    // SAFETY: forwarded from this function's contract.
    unsafe { crate::cpu::read_msr(IA32_EFER) & EFER_SCE != 0 }
}

#[cfg(not(test))]
unsafe extern "C" {
    /// The entry stub, defined below. Its address is what goes in `IA32_LSTAR`.
    fn staros_syscall_entry();
}

#[cfg(not(test))]
core::arch::global_asm!(
    r#"
.section .text
.globl staros_syscall_entry
staros_syscall_entry:
    /* Ring 0 already, and still on the user's stack: nothing may be pushed until
       the two instructions below have run. `swapgs` is the only way to reach
       memory here without a spare register, because every register still holds
       something that belongs to the caller. */
    swapgs
    mov     gs:[{off_scratch}], rsp
    mov     rsp, gs:[{off_kernel}]

    /* The frame, in SyscallFrame's field order: pushed from the last field to
       the first, so `rax` ends up at the lowest address. */
    push    qword ptr gs:[{off_scratch}]    /* user_rsp */
    push    r11                             /* rflags, per the instruction */
    push    rcx                             /* rip, per the instruction */
    push    r9
    push    r8
    push    r10
    push    rdx
    push    rsi
    push    rdi
    push    rax
    /* Ten pushes is 80 bytes, so a 16-aligned kernel stack top is still
       16-aligned here, and the `call` below leaves the callee with the 8-mod-16
       System V wants. */
    cld
    mov     rdi, rsp
    call    staros_syscall_dispatch
    test    rax, rax
    jnz     2f

    /* The fast way back. Safe only because the dispatcher checked that the RIP
       about to go into RCX is canonical. */
    pop     rax
    pop     rdi
    pop     rsi
    pop     rdx
    pop     r10
    pop     r8
    pop     r9
    pop     rcx
    pop     r11
    pop     rsp
    /* Between here and `sysretq` this core is in ring 0 on the *user's* stack.
       Interrupts are still masked (FMASK cleared IF and nothing set it), and the
       one thing that could still arrive — an NMI — has its own IST stack, so
       nothing is pushed here. */
    swapgs
    sysretq

2:  /* The slow way back, taken when RIP is non-canonical. `iretq` loads RIP
       through the same path as any exception return, so a bad address faults in
       ring 3 with the user's CS instead of in ring 0 with ours. */
    mov     rax, [rsp + {off_frame_user_rsp}]
    mov     gs:[{off_scratch}], rax
    pop     rax
    pop     rdi
    pop     rsi
    pop     rdx
    pop     r10
    pop     r8
    pop     r9
    pop     rcx                             /* rip */
    pop     r11                             /* rflags */
    add     rsp, 8                          /* drop the copied user_rsp */
    push    {user_ss}
    push    qword ptr gs:[{off_scratch}]
    push    r11
    push    {user_cs}
    push    rcx
    /* After this `gs:` would be the user's base, so every access above had to
       come first. */
    swapgs
    iretq
"#,
    off_kernel = const OFF_KERNEL_RSP,
    off_scratch = const OFF_SCRATCH_RSP,
    off_frame_user_rsp = const core::mem::offset_of!(SyscallFrame, user_rsp),
    user_ss = const crate::gdt::USER_DATA,
    user_cs = const crate::gdt::USER_CODE,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdt;

    /// The derivation, checked against the table it derives from. A wrong base
    /// here builds, boots, and loads a plausible wrong selector on the first
    /// return to ring 3 — the failure this test exists because nothing else
    /// catches.
    #[test]
    fn star_derives_the_selectors_the_gdt_actually_has() {
        let star = star_value(gdt::KERNEL_CODE, gdt::USER_CODE32 & !3);
        assert_eq!(syscall_cs(star), gdt::KERNEL_CODE);
        assert_eq!(syscall_ss(star), gdt::KERNEL_DATA);
        assert_eq!(sysret_cs(star), gdt::USER_CODE);
        assert_eq!(sysret_ss(star), gdt::USER_DATA);
    }

    /// The layout constraint the derivation imposes on the GDT, stated as itself:
    /// kernel data must follow kernel code, and the user entries must run 32-bit
    /// code, data, 64-bit code with no gaps. Reordering the table is the other way
    /// to break `sysret`, and it would leave the test above passing if that test
    /// were written against literals.
    #[test]
    fn the_gdt_is_laid_out_the_way_sysret_requires() {
        assert_eq!(gdt::KERNEL_DATA, gdt::KERNEL_CODE + 8);
        assert_eq!(gdt::USER_DATA & !3, (gdt::USER_CODE32 & !3) + 8);
        assert_eq!(gdt::USER_CODE & !3, (gdt::USER_CODE32 & !3) + 16);
    }

    /// Both selectors `sysret` forges must name ring 3. A base that produced RPL
    /// 0 would return to user code running with kernel privilege, which faults
    /// nowhere and reports nothing.
    #[test]
    fn sysret_returns_to_ring_three() {
        let star = star_value(gdt::KERNEL_CODE, gdt::USER_CODE32 & !3);
        assert_eq!(sysret_cs(star) & 3, 3);
        assert_eq!(sysret_ss(star) & 3, 3);
    }

    /// The two the roadmap names, and the one that quietly undoes phase 1.4.
    #[test]
    fn fmask_clears_the_flags_the_kernel_cannot_let_the_caller_choose() {
        assert_ne!(FMASK & RFLAGS_IF, 0, "an interrupt would land on the user stack");
        assert_ne!(FMASK & RFLAGS_TF, 0, "a user debugger would single-step the kernel");
        assert_ne!(FMASK & RFLAGS_AC, 0, "ring 3 could switch SMAP off for the kernel");
        assert_ne!(FMASK & RFLAGS_DF, 0);
        assert_ne!(FMASK & RFLAGS_NT, 0);
        assert_ne!(FMASK & RFLAGS_RF, 0);
    }

    /// FMASK must not clear the bits that are not the caller's to lose. Carry,
    /// zero and the rest are ordinary results; a mask that took them would make
    /// every syscall corrupt the caller's condition codes.
    #[test]
    fn fmask_leaves_the_condition_codes_alone() {
        const CF: u64 = 1 << 0;
        const ZF: u64 = 1 << 6;
        const SF: u64 = 1 << 7;
        const OF: u64 = 1 << 11;
        assert_eq!(FMASK & (CF | ZF | SF | OF), 0);
    }

    /// The canonical rule, at both boundaries and on both sides of the hole.
    #[test]
    fn canonical_is_the_sign_extension_of_bit_47() {
        assert!(is_canonical(0));
        assert!(is_canonical(0x0000_7FFF_FFFF_FFFF), "last low-half address");
        assert!(!is_canonical(0x0000_8000_0000_0000), "first address in the hole");
        assert!(!is_canonical(0x7FFF_FFFF_FFFF_FFFF));
        assert!(!is_canonical(0xFFFF_7FFF_FFFF_FFFF), "last address in the hole");
        assert!(is_canonical(0xFFFF_8000_0000_0000), "first high-half address");
        assert!(is_canonical(0xFFFF_FFFF_FFFF_FFFF));
        // The kernel's own addresses, which `sysret` must never see but which the
        // check has to accept as valid: they are in the high half.
        assert!(is_canonical(0xFFFF_FFFF_8000_0000));
    }

    /// A user program's address space is the low half, and every address in it is
    /// canonical — so the check must never reject an ordinary return.
    #[test]
    fn every_user_address_is_canonical() {
        for address in [0x40_0000u64, 0x41_0000, 0x7FFF_F000, 0x0000_7FFF_FFFF_F000] {
            assert!(is_canonical(address), "{address:#x}");
        }
    }

    /// The frame the assembly builds, field by field. A push too many or too few
    /// shifts every field: the syscall number reads as an argument, and the
    /// return address as flags.
    #[test]
    fn the_frame_is_the_layout_the_stub_pushes() {
        assert_eq!(core::mem::size_of::<SyscallFrame>(), 80);
        assert_eq!(core::mem::offset_of!(SyscallFrame, rax), 0);
        assert_eq!(core::mem::offset_of!(SyscallFrame, rdi), 8);
        assert_eq!(core::mem::offset_of!(SyscallFrame, rsi), 16);
        assert_eq!(core::mem::offset_of!(SyscallFrame, rdx), 24);
        assert_eq!(core::mem::offset_of!(SyscallFrame, r10), 32);
        assert_eq!(core::mem::offset_of!(SyscallFrame, r8), 40);
        assert_eq!(core::mem::offset_of!(SyscallFrame, r9), 48);
        assert_eq!(core::mem::offset_of!(SyscallFrame, rip), 56);
        assert_eq!(core::mem::offset_of!(SyscallFrame, rflags), 64);
        assert_eq!(core::mem::offset_of!(SyscallFrame, user_rsp), 72);
    }

    /// Eighty bytes is five sixteen-byte units, so a 16-aligned kernel stack is
    /// still 16-aligned under the frame and the `call` that follows meets the ABI.
    /// An odd number of pushes would misalign every syscall.
    #[test]
    fn the_frame_keeps_the_stack_aligned() {
        assert_eq!(core::mem::size_of::<SyscallFrame>() % 16, 0);
    }

    /// The block the stub reaches through `GS`, at the offsets it uses.
    #[test]
    fn the_percpu_offsets_are_the_layout() {
        assert_eq!(core::mem::offset_of!(PerCpu, kernel_rsp), OFF_KERNEL_RSP);
        assert_eq!(core::mem::offset_of!(PerCpu, scratch_rsp), OFF_SCRATCH_RSP);
    }

    /// The dispatcher's answer is a `u64` in `RAX` that the assembly tests
    /// against zero, so `Sysret` must be the zero one.
    #[test]
    fn the_fast_path_is_the_zero_discriminant() {
        assert_eq!(Return::Sysret as u64, 0);
        assert_ne!(Return::Iret as u64, 0);
    }
}
