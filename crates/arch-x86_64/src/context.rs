//! Context switching between kernel tasks.
//!
//! The counterpart of `../../../kernel-new/crates/arch-aarch64/src/context.rs`,
//! and the one place in phase 2 where x86_64 is the *simpler* architecture: a
//! switch happens at an ordinary function-call boundary, so only the callee-saved
//! registers have to be saved, and System V names six of them — `RBX`, `RBP`,
//! `R12`, `R13`, `R14`, `R15` — plus `RSP`. AArch64 names nineteen. Everything
//! else is caller-saved and already dead across the call.
//!
//! ## The difference that is not a simplification
//! AArch64 has a link register. Starting a fresh task there is a matter of
//! writing the trampoline's address into the saved `x30` and letting `ret` branch
//! to it. x86 has no link register: `ret` takes its target *off the stack*. So a
//! new task cannot be bootstrapped by setting a register — the first frame has to
//! be **built on the task's own stack**, with the trampoline's address planted
//! where `ret` will look for it. That is [`plant`], and it is the only part of
//! this module that can be tested off a CPU, so it is separated out and tested.
//!
//! Getting it wrong is silent in the worst way. `ret` will happily pop whatever
//! word is at the top of a fresh stack — zero, on a zeroed allocation — and jump
//! to address 0, which since phase 1.4 is a `#PF` at zero rather than a walk into
//! whatever the loader left mapped. That is a readable failure only because the
//! null page is deliberately absent; it would otherwise be a wild jump.
//!
//! ## Alignment is a contract, not a courtesy
//! System V requires `RSP + 8` to be 16-byte aligned at the *first instruction*
//! of a function — i.e. `RSP` is 16-aligned immediately before a `call`. SSE
//! instructions that the compiler emits for ordinary struct moves fault on a
//! misaligned stack (`#GP`, from `movaps`), and they will not appear until some
//! unrelated code grows a wide enough local. So the planted frame is built to
//! satisfy the ABI from the trampoline's first instruction onward, and [`plant`]
//! asserts it in host tests rather than leaving it to be discovered.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The scheduler callbacks the trampoline needs, as raw function pointers.
///
/// The trampoline has to call back into the kernel twice — once to settle the
/// task this core switched away from, once when the task's entry function
/// returns — and the aarch64 tree does that by *name*, letting the link resolve
/// symbols the scheduler defines. That does not work here, and the reason is
/// specific to this port: the same `staros-arch-x86-64` rlib is linked into the
/// **UEFI loader**, which has no scheduler and never will. Assembly emitted by
/// `global_asm!` is not subject to per-symbol garbage collection, so the
/// trampoline's `call`s survive into a binary that cannot satisfy them, and the
/// loader fails to link with two undefined symbols it has no business knowing
/// about.
///
/// So the crate defines the symbols itself and dispatches through pointers the
/// kernel registers — exactly the arrangement [`crate::trap::set_handler`]
/// already uses, and for the same reason: this crate is the mechanism, and the
/// mechanism must not depend on one particular binary's policy existing.
static POST_SWITCH: AtomicUsize = AtomicUsize::new(0);
/// See [`POST_SWITCH`].
static TASK_EXIT: AtomicUsize = AtomicUsize::new(0);

/// Register what the task trampoline calls.
///
/// `post_switch` runs with interrupts still masked, before the new task's body;
/// `task_exit` runs when that body returns and must never come back.
///
/// Not `unsafe`: both pointers come from safe `fn` items, and the only thing done
/// with them is a call.
pub fn set_hooks(post_switch: fn(), task_exit: fn() -> !) {
    POST_SWITCH.store(post_switch as usize, Ordering::SeqCst);
    TASK_EXIT.store(task_exit as usize, Ordering::SeqCst);
}

/// Called by the trampoline before a brand-new task runs its own code.
#[cfg(not(test))]
#[no_mangle]
extern "C" fn staros_post_switch() {
    let hook = POST_SWITCH.load(Ordering::SeqCst);
    if hook == 0 {
        // A task started with no scheduler registered. Nothing sensible follows,
        // and carrying on would run the task without settling its predecessor.
        crate::cpu::halt()
    }
    // SAFETY: `hook` was stored from a `fn()` item by `set_hooks` and from
    // nowhere else, so the transmute reverses exactly the cast that produced it.
    let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(hook) };
    hook();
}

/// Called by the trampoline when a task's entry function returns.
#[cfg(not(test))]
#[no_mangle]
extern "C" fn staros_task_exit() -> ! {
    let hook = TASK_EXIT.load(Ordering::SeqCst);
    if hook == 0 {
        crate::cpu::halt()
    }
    // SAFETY: as `staros_post_switch`.
    let hook: fn() -> ! = unsafe { core::mem::transmute::<usize, fn() -> !>(hook) };
    hook()
}

/// Byte offsets of the saved registers, shared between the Rust layout and the
/// assembly that reads it.
///
/// They are handed to `global_asm!` as `const` operands rather than written twice:
/// two lists of the same numbers is exactly the kind of duplication that drifts,
/// and a wrong offset here does not fail to build — it restores `R13` into `R12`
/// and produces a task that runs on someone else's data.
const OFF_RBX: usize = 0;
const OFF_RBP: usize = 8;
const OFF_R12: usize = 16;
const OFF_R13: usize = 24;
const OFF_R14: usize = 32;
const OFF_R15: usize = 40;
const OFF_RSP: usize = 48;

/// Saved callee-saved CPU state for a suspended task.
///
/// `#[repr(C)]`, and mirrored exactly by the offsets above.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuContext {
    /// `RBX`, `RBP`, `R12`, `R13`, `R14`, `R15`, in that order.
    regs: [u64; 6],
    /// Stack pointer.
    rsp: u64,
}

/// Index of `RBX` in [`CpuContext::regs`]. A fresh task's entry function is
/// parked here, because the trampoline needs it after a call that clobbers
/// everything caller-saved.
#[cfg(not(test))]
const REG_RBX: usize = 0;

impl CpuContext {
    /// An all-zero context, suitable as the destination of the first switch (its
    /// contents are overwritten before it is ever restored).
    #[must_use]
    pub const fn empty() -> Self {
        Self { regs: [0; 6], rsp: 0 }
    }

    /// The saved stack pointer. Read by tests and by the boot log; the scheduler
    /// never needs it.
    #[must_use]
    pub const fn rsp(&self) -> u64 {
        self.rsp
    }

    /// Prepare a fresh task: on first switch it starts at the trampoline, which
    /// calls `entry` on `stack`.
    ///
    /// Returns `false` when `stack` is too short to hold the planted frame, which
    /// is a caller error rather than a machine state — a task with nowhere to
    /// stand must not be created.
    ///
    /// # Panics
    /// Never. The fallible case is the return value.
    #[cfg(not(test))]
    pub fn init(&mut self, entry: extern "C" fn(), stack: &mut [u64]) -> bool {
        let Some(rsp) = plant(stack, __task_trampoline as *const () as u64) else {
            return false;
        };
        // Zeroing the block also zeroes `RBP`, which ends the frame-pointer chain
        // at the task's entry instead of walking into whatever the switching-out
        // core happened to be holding.
        self.regs = [0; 6];
        // `RBX` survives the trampoline's call to `staros_post_switch`, which is
        // the whole reason the entry pointer is parked in a callee-saved register
        // rather than in `RDI`.
        self.regs[REG_RBX] = entry as *const () as u64;
        self.rsp = rsp;
        true
    }
}

/// Build a fresh task's first stack frame and return the `RSP` a switch should
/// load to enter it.
///
/// The frame is one word: the address `__context_switch`'s final `ret` will pop
/// and jump to. It sits at the highest 16-byte-aligned address in `stack` minus
/// eight, so that after `ret` has consumed it `RSP` is 16-aligned — which is the
/// state the ABI says a function body may assume, and the state the trampoline's
/// own `call`s depend on.
///
/// Returns `None` if `stack` has no room for that word.
#[must_use]
pub fn plant(stack: &mut [u64], trampoline: u64) -> Option<u64> {
    let base = stack.as_mut_ptr() as u64;
    let bytes = (stack.len() as u64).checked_mul(8)?;
    // Round *down*: a `Box<[u64]>` promises 8-byte alignment, so the top of the
    // allocation is not necessarily 16-aligned and assuming it would misalign
    // every frame in the task by eight bytes.
    let top = (base.checked_add(bytes)?) & !0xf;
    if top < base + 8 {
        return None;
    }
    let rsp = top - 8;
    // Index rather than a raw store: the same arithmetic, but bounds-checked, and
    // it is what lets this run under a host test harness at all.
    let index = usize::try_from((rsp - base) / 8).ok()?;
    *stack.get_mut(index)? = trampoline;
    Some(rsp)
}

#[cfg(not(test))]
unsafe extern "C" {
    /// Save the current callee-saved context into `prev` and load `next`.
    fn __context_switch(prev: *mut CpuContext, next: *const CpuContext);
    /// Entry trampoline for freshly-created tasks (see the module docs).
    fn __task_trampoline();
}

/// Switch the current CPU context to `next`, saving the outgoing state into
/// `prev`. When `prev` is later switched back to, execution resumes right here.
///
/// # Safety
/// Both pointers must reference valid, non-overlapping [`CpuContext`]s, and
/// `next` must either have been saved by a previous switch or prepared by
/// [`CpuContext::init`]. Interrupts must be masked across the call: the switch is
/// not atomic with respect to the scheduler state that chose `prev` and `next`.
#[cfg(not(test))]
pub unsafe fn context_switch(prev: *mut CpuContext, next: *const CpuContext) {
    // SAFETY: forwarded to the caller; `__context_switch` reads and writes only
    // the two contexts and swaps `RSP`.
    unsafe { __context_switch(prev, next) }
}

// The trampoline `call`s `staros_post_switch` and `staros_task_exit`, both
// defined above in this crate, which forward to whatever `set_hooks` registered.
#[cfg(not(test))]
core::arch::global_asm!(
    r#"
.section .text
.globl __context_switch
/* rdi = prev (*mut CpuContext), rsi = next (*const CpuContext) */
__context_switch:
    mov     [rdi + {off_rbx}], rbx
    mov     [rdi + {off_rbp}], rbp
    mov     [rdi + {off_r12}], r12
    mov     [rdi + {off_r13}], r13
    mov     [rdi + {off_r14}], r14
    mov     [rdi + {off_r15}], r15
    mov     [rdi + {off_rsp}], rsp

    mov     rbx, [rsi + {off_rbx}]
    mov     rbp, [rsi + {off_rbp}]
    mov     r12, [rsi + {off_r12}]
    mov     r13, [rsi + {off_r13}]
    mov     r14, [rsi + {off_r14}]
    mov     r15, [rsi + {off_r15}]
    mov     rsp, [rsi + {off_rsp}]
    /* The return address comes off `next`'s stack, not this one. For a task
       being resumed that is the `call __context_switch` it suspended in; for a
       fresh task it is the word `plant` put there. */
    ret

.globl __task_trampoline
__task_trampoline:
    /* Settle (and, if it exited, reap) the task this core switched away from,
       while interrupts are still masked as the switching-out core left them. */
    call    staros_post_switch
    /* The newly-started task runs with interrupts enabled — this is the x86
       counterpart of `msr daifclr, #2`. */
    sti
    /* RBX holds the entry function: parked there by `CpuContext::init` because
       it is callee-saved and therefore survived the call above. */
    call    rbx
    /* The entry returned, so the task is over. Does not return. */
    call    staros_task_exit
    ud2
"#,
    off_rbx = const OFF_RBX,
    off_rbp = const OFF_RBP,
    off_r12 = const OFF_R12,
    off_r13 = const OFF_R13,
    off_r14 = const OFF_R14,
    off_r15 = const OFF_R15,
    off_rsp = const OFF_RSP,
);

#[cfg(test)]
mod tests {
    use super::*;

    /// The offsets the assembly indexes with must be the offsets the Rust type
    /// actually has. Nothing else checks this: a wrong number assembles, links
    /// and runs, and restores the wrong register.
    #[test]
    fn the_offsets_are_the_layout() {
        let ctx = CpuContext::empty();
        let base = std::ptr::from_ref(&ctx) as usize;
        let regs = std::ptr::from_ref(&ctx.regs) as usize;
        let rsp = std::ptr::from_ref(&ctx.rsp) as usize;
        assert_eq!(regs - base, OFF_RBX);
        assert_eq!(regs - base + 8, OFF_RBP);
        assert_eq!(regs - base + 16, OFF_R12);
        assert_eq!(regs - base + 24, OFF_R13);
        assert_eq!(regs - base + 32, OFF_R14);
        assert_eq!(regs - base + 40, OFF_R15);
        assert_eq!(rsp - base, OFF_RSP);
        assert_eq!(core::mem::size_of::<CpuContext>(), 56);
    }

    #[test]
    fn an_empty_context_is_all_zero() {
        let ctx = CpuContext::empty();
        assert_eq!(ctx.regs, [0; 6]);
        assert_eq!(ctx.rsp(), 0);
    }

    /// The planted word is what `ret` will jump to, so it has to be *the*
    /// trampoline address, at exactly the address the returned `RSP` names.
    #[test]
    fn the_trampoline_is_where_ret_will_look_for_it() {
        let mut stack = vec![0u64; 512];
        let base = stack.as_ptr() as u64;
        let rsp = plant(&mut stack, 0xDEAD_BEEF_0000_1000).expect("room for one word");
        assert!(rsp >= base && rsp < base + 512 * 8);
        let index = ((rsp - base) / 8) as usize;
        assert_eq!(stack[index], 0xDEAD_BEEF_0000_1000);
    }

    /// The ABI condition, stated as the ABI states it: 16-byte aligned `RSP` at
    /// the first instruction of the trampoline, which is one `ret`-pop above the
    /// planted frame.
    #[test]
    fn the_stack_is_aligned_the_way_system_v_requires() {
        // Several lengths, because the allocation's own alignment varies and the
        // rounding has to absorb it rather than pass it on.
        for len in [2usize, 3, 511, 512, 4096] {
            let mut stack = vec![0u64; len];
            let rsp = plant(&mut stack, 0x1000).expect("room for one word");
            assert_eq!(rsp % 16, 8, "len {len}: RSP before `ret` must be 8 mod 16");
            assert_eq!((rsp + 8) % 16, 0, "len {len}: RSP at the trampoline must be 16-aligned");
        }
    }

    /// An allocation that starts 8-mod-16 is the case that catches a `top` which
    /// was assumed aligned rather than rounded down: without the rounding, every
    /// frame in the task is eight bytes out and the first `movaps` faults.
    #[test]
    fn an_oddly_aligned_allocation_still_lands_aligned() {
        let mut backing = vec![0u64; 64];
        let base = backing.as_ptr() as u64;
        // Slice off a word if needed so the region begins at 8 mod 16.
        let skew = usize::from(base % 16 == 0);
        let stack = &mut backing[skew..];
        assert_eq!(stack.as_ptr() as u64 % 16, 8);
        let rsp = plant(stack, 0x2000).expect("room for one word");
        assert_eq!((rsp + 8) % 16, 0);
    }

    /// The whole planted word must lie inside the stack, never one past its end.
    #[test]
    fn the_frame_is_inside_the_allocation() {
        let mut stack = vec![0u64; 16];
        let base = stack.as_ptr() as u64;
        let end = base + 16 * 8;
        let rsp = plant(&mut stack, 0x3000).expect("room for one word");
        assert!(rsp + 8 <= end, "the planted word runs past the stack");
    }

    /// A stack with no room for the frame is a refusal, not a wild write.
    #[test]
    fn a_stack_too_short_is_refused() {
        let mut nothing: Vec<u64> = Vec::new();
        assert_eq!(plant(&mut nothing, 0x4000), None);
    }

    /// Planting does not disturb the rest of the stack: a task's locals start
    /// zeroed, and a `plant` that scribbled would be found only by whatever read
    /// the garbage.
    #[test]
    fn only_one_word_is_written() {
        let mut stack = vec![0u64; 64];
        let base = stack.as_ptr() as u64;
        let rsp = plant(&mut stack, 0x5000).expect("room for one word");
        let planted = ((rsp - base) / 8) as usize;
        for (i, word) in stack.iter().enumerate() {
            if i == planted {
                continue;
            }
            assert_eq!(*word, 0, "word {i} was written");
        }
    }
}
