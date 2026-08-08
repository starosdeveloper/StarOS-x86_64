//! Ring 3: the program, the pages it runs in, and the syscalls it makes.
//!
//! The policy half of phase 3.1. [`staros_arch_x86_64::syscall`] and
//! [`staros_arch_x86_64::usermode`] own the mechanism — the MSRs, the entry stub,
//! the `iretq` frame; this module decides what ring 3 is allowed to do and proves
//! it can.
//!
//! ## Where the program comes from
//! Nowhere yet. Phase 3.2 brings the ELF loader and a private address space per
//! task; until then the program is a hand-written blob assembled into this
//! kernel's `.rodata` and **copied** into a fresh frame, which is then mapped
//! user-executable at [`USER_CODE`]. Copied rather than mapped in place, because
//! the kernel image's frames are mapped read-execute for ring 0 and giving ring 3
//! a second, user-accessible window onto them would hand user space the kernel's
//! own text.
//!
//! The copy goes through the *linear map* — the kernel's alias of that frame —
//! not through the user mapping. That is not an optimisation. `CR4.SMAP` has been
//! on since phase 1.4, so a ring-0 store to a user-mapped address faults, and the
//! kernel writing the program through the address the program will run at would
//! be the first thing to break.
//!
//! ## Three pages, three different rights
//! | page | rights | why that and not more |
//! |---|---|---|
//! | [`USER_CODE`] | user, read, **execute**, not writable | W^X. A writable code page is a program that can rewrite itself, and there is no reason for one here |
//! | [`USER_STACK`] | user, read, write, **not executable** | the other half of W^X, and the one that matters: an executable stack is where a stack-smash becomes code execution |
//! | [`USER_CLOCK`] | user, **read only** | the tick counter. Ring 3 needs to be able to tell time to bound its own loop; it has no business setting it |
//!
//! The clock page deserves its own note, because it is doing something a syscall
//! could do instead. A ring-3 program that wants to run "for about a third of a
//! second" has no other way to know: the timer is the kernel's, and adding a
//! syscall for it would mean changing the ABI both trees share for the sake of one
//! self-test. A read-only page the kernel writes and user space reads is the
//! standard answer (it is what a vDSO clock is), it costs one store per tick, and
//! it makes the test's duration a property of the machine's clock rather than of a
//! spin count guessed against the slowest emulator.
//!
//! ## What ring 3 may call
//! `Yield`, `Exit` and `DebugWrite`, out of the twenty numbers
//! [`staros_abi::syscall::Syscall`] defines. Everything else answers
//! [`KError::NoSuchSyscall`] — not because it is unimplementable, but because a
//! syscall that returns a plausible value without doing anything is worse than one
//! that says no.
//!
//! `DebugWrite` is the interesting one and the reason it is here rather than
//! `DebugPutc`. It takes a **pointer into ring 3's memory**, which means the
//! kernel has to answer two questions it has never had to answer before: is this
//! address one the caller may read, and how does ring 0 read it at all with SMAP
//! on. The first is [`crate::vm::user_range_ok`], which *walks the page tables*
//! rather than range-checking, because being in the user half proves nothing. The
//! second is `stac`/`clac` around the copy, which is the only place in this kernel
//! that opens the SMAP window and closes it again.

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use staros_abi::error::KError;
use staros_abi::syscall::Syscall;
use staros_arch_x86_64::syscall::{self as arch_syscall, SyscallFrame};
use staros_arch_x86_64::{cpu, usermode};
use staros_paging::{Rights, PAGE_SIZE};

use crate::console::Console;
use crate::sync::SpinLock;
use crate::vm::Tables;
use crate::{mem, sched, vm};

/// Where the program's code is mapped. 4 MiB — the address a linker gives a
/// non-PIE ELF by default, so phase 3.2 can load a real one here without moving
/// anything.
const USER_CODE: u64 = 0x0000_0000_0040_0000;
/// Where the read-only tick counter is mapped.
const USER_CLOCK: u64 = 0x0000_0000_0041_0000;
/// The one stack page. The top is one page above, and 16-byte aligned because it
/// is page aligned.
const USER_STACK: u64 = 0x0000_0000_7FFF_F000;
/// The stack pointer ring 3 starts with.
const USER_STACK_TOP: u64 = USER_STACK + PAGE_SIZE;

/// How many timer ticks the program spins in ring 3 before doing anything else.
///
/// Thirty at 100 Hz is 300 ms. Its only job is to be long enough that the timer
/// *must* interrupt ring 3 — which is the thing being tested, since an interrupt
/// from ring 3 is the one transition that cannot work without `TSS.rsp0`.
const USER_RUN_TICKS: u64 = 30;

/// A non-canonical address: bit 47 clear, bits above it set.
///
/// Handed to `sysretq` this is a `#GP` **in ring 0**. It is the value the
/// experiment below forces as a return address, and the whole point is that the
/// fault it causes must arrive in ring 3 instead.
const NONCANONICAL_RIP: u64 = 0x0000_8000_0000_0000;

/// Longest buffer `DebugWrite` will copy in one call.
///
/// A cap rather than a loop, and it is a security parameter, not a convenience:
/// the buffer lands on the kernel stack, and a length ring 3 chooses is a length
/// ring 3 chooses. Without this the syscall is a stack overflow with a user-space
/// trigger.
const DEBUG_WRITE_MAX: usize = 256;

/// The live page tables, kept so a syscall can validate a user pointer against
/// the tree the CPU is actually walking.
static TABLES: SpinLock<Option<Tables>> = SpinLock::new(None);

/// Kernel address of the clock page — the linear-map alias, which is how the tick
/// writes to a page ring 3 sees as read-only. Zero until [`init`].
static CLOCK_KERNEL_VA: AtomicUsize = AtomicUsize::new(0);

/// Syscalls served, by kind. Counted rather than logged: `DebugWrite` is called
/// twice and `Yield` once, so the numbers are a statement about the program's
/// path through the kernel that a line of output could not make.
static SYSCALLS: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);
static BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// Set when the next syscall's return address should be corrupted. See
/// [`selftest_noncanonical`].
static ARM_NONCANONICAL: AtomicBool = AtomicBool::new(false);

/// Faults taken in ring 3, which kill the task and nothing else.
static USER_FAULTS: AtomicU64 = AtomicU64::new(0);

/// Ring-3 faults so far, and what the last one was.
#[must_use]
pub fn user_faults() -> u64 {
    USER_FAULTS.load(Ordering::Relaxed)
}

/// Record that a fault arrived from ring 3. Called by the trap handler before it
/// kills the task.
pub fn note_user_fault() {
    USER_FAULTS.fetch_add(1, Ordering::Relaxed);
}

/// Publish the current tick count to the page ring 3 reads.
///
/// Called from the timer interrupt, so it is deliberately three instructions and
/// takes no lock. A volatile store rather than an atomic one because there is
/// exactly one writer (this core's timer) and one reader (this core's ring-3
/// program), and they are the same core: the store cannot be torn by anything,
/// and the reader is a `mov` that either sees the old value or the new one.
pub fn publish_ticks(ticks: u64) {
    let at = CLOCK_KERNEL_VA.load(Ordering::Relaxed);
    if at == 0 {
        return;
    }
    // SAFETY: `at` is the linear-map alias of a frame this module allocated and
    // owns, written only here. The linear map is live for the whole life of the
    // kernel and this address is 8-byte aligned (it is page aligned).
    unsafe { (at as *mut u64).write_volatile(ticks) };
}

// The ring-3 program. Assembled into this kernel's `.rodata` and copied out; see
// the module documentation for why it is not mapped in place.
//
// Everything in it is position independent — `lea` off `rip` for the strings,
// absolute immediates only for the fixed mapping addresses — because it is
// assembled at one address and executed at another.
core::arch::global_asm!(
    r#"
.section .rodata
.globl __staros_user_start
__staros_user_start:
    /* Say hello, in one syscall. `DebugWrite` rather than a byte at a time: the
       kernel console lock makes one call one message, and a per-byte loop would
       interleave with the other task's output. */
    lea     rdi, [rip + .Lstaros_user_hello]
    call    .Lstaros_user_puts

    /* Spin in ring 3 until the kernel's clock has advanced. Nothing here enters
       the kernel, so every tick counted during this loop is an interrupt taken
       *from ring 3* — which is only possible if TSS.rsp0 holds a kernel stack. */
    mov     r12, {clock}
    mov     r13, [r12]
    add     r13, {run_ticks}
.Lstaros_user_spin:
    mov     r14, [r12]
    cmp     r14, r13
    jb      .Lstaros_user_spin

    /* Give the CPU up on purpose. Down through `syscall`, out through the
       scheduler, back in through `sysretq`, and the next instruction runs. */
    mov     eax, {sys_yield}
    syscall

    lea     rdi, [rip + .Lstaros_user_bye]
    call    .Lstaros_user_puts

    mov     eax, {sys_exit}
    syscall
    /* `Exit` does not return. If it does, this is a fault rather than a walk
       into whatever follows in the page. */
    ud2

    /* Write the NUL-terminated string at RDI. User space measures its own
       strings rather than the assembler doing it: a label difference written
       inline is a memory expression to the Intel-syntax parser, and the loop is
       what a C runtime would do here anyway. Uses `call`/`ret`, so it also
       proves the ring-3 stack is writable. */
.Lstaros_user_puts:
    mov     rsi, rdi
    xor     ecx, ecx
.Lstaros_user_strlen:
    cmp     byte ptr [rsi + rcx], 0
    je      .Lstaros_user_write
    inc     rcx
    jmp     .Lstaros_user_strlen
.Lstaros_user_write:
    mov     rsi, rcx
    mov     eax, {sys_debug_write}
    /* RCX and R11 are destroyed by the instruction; neither is live here. */
    syscall
    ret

.Lstaros_user_hello:
    .asciz "user: hello from ring 3\n"
.Lstaros_user_bye:
    .asciz "user: preempted while in ring 3, yielded, and came back\n"
.globl __staros_user_end
__staros_user_end:
"#,
    sys_debug_write = const Syscall::DebugWrite as usize,
    sys_yield = const Syscall::Yield as usize,
    sys_exit = const Syscall::Exit as usize,
    clock = const USER_CLOCK,
    run_ticks = const USER_RUN_TICKS,
);

unsafe extern "C" {
    /// First byte of the ring-3 program, in this kernel's `.rodata`.
    static __staros_user_start: u8;
    /// One past its last byte.
    static __staros_user_end: u8;
}

/// Build the ring-3 address space and turn `syscall` on.
///
/// # Errors
/// Names whichever page could not be allocated or mapped. All of them are fatal
/// to the phase: a program with no stack, no code or no clock is not a program.
///
/// # Safety
/// Called once, on the boot core, after `vm::init` and `gdt::install`, with
/// interrupts masked.
pub unsafe fn init(console: &mut Console, tables: &Tables) -> Result<(), &'static str> {
    let blob_start = (&raw const __staros_user_start) as u64;
    let blob_end = (&raw const __staros_user_end) as u64;
    let blob_len = blob_end - blob_start;
    if blob_len == 0 || blob_len > PAGE_SIZE {
        return Err("the ring-3 program does not fit in one page");
    }

    let code = mem::alloc_frame().ok_or("no frame for the ring-3 program")?.0 as u64;
    let stack = mem::alloc_frame().ok_or("no frame for the ring-3 stack")?.0 as u64;
    let clock = mem::alloc_frame().ok_or("no frame for the ring-3 clock")?.0 as u64;

    // Through the kernel's alias, never through the user mapping — see the module
    // documentation on SMAP.
    let code_kernel = staros_bootinfo::phys_to_virt(code) as *mut u8;
    let stack_kernel = staros_bootinfo::phys_to_virt(stack) as *mut u8;
    let clock_kernel = staros_bootinfo::phys_to_virt(clock) as *mut u8;
    // SAFETY: three frames just allocated exclusively from the pool, each mapped
    // read/write through the linear map, each a whole page. The buddy allocator
    // recycles frames without clearing them, so a stack handed to ring 3 unzeroed
    // would leak whatever the kernel last put there.
    unsafe {
        core::ptr::write_bytes(code_kernel, 0, PAGE_SIZE as usize);
        core::ptr::write_bytes(stack_kernel, 0, PAGE_SIZE as usize);
        core::ptr::write_bytes(clock_kernel, 0, PAGE_SIZE as usize);
        core::ptr::copy_nonoverlapping(blob_start as *const u8, code_kernel, blob_len as usize);
    }
    CLOCK_KERNEL_VA.store(clock_kernel as usize, Ordering::SeqCst);
    // Seed it with the count as it stands, *before* ring 3 can read it. The
    // counter is cumulative from the first tick this kernel ever took, so a page
    // left at zero tells the program it is at time zero — and its "wait thirty
    // ticks" becomes "wait for a number already several hundred in the past",
    // satisfied by the first tick that arrives. Which looks exactly like a
    // working test, and reports two preemptions instead of fifteen.
    publish_ticks(crate::irq::ticks());

    // W^X, both ways round. `Rights::RX` has no write bit and `Rights::RW` has no
    // execute bit; `to_user` adds ring-3 reachability and changes neither.
    // SAFETY: three frames this module owns, none aliased to anything ring 3 is
    // not meant to see, mapped into the live tree.
    unsafe {
        vm::map_user(tables, USER_CODE, code, PAGE_SIZE, Rights::RX.to_user())?;
        vm::map_user(tables, USER_STACK, stack, PAGE_SIZE, Rights::RW.to_user())?;
        vm::map_user(tables, USER_CLOCK, clock, PAGE_SIZE, Rights::RO.to_user())?;
    }
    *TABLES.lock() = Some(*tables);

    // SAFETY: the GDT is installed and holds the selectors `IA32_STAR` names; the
    // handler below is registered before anything can call it; nothing is in
    // ring 3 yet.
    unsafe { arch_syscall::init() };
    arch_syscall::set_handler(on_syscall);
    // SAFETY: ring 0.
    if !unsafe { arch_syscall::is_enabled() } {
        return Err("IA32_EFER.SCE did not take: `syscall` is still an invalid opcode");
    }

    let star = arch_syscall::star_value(
        staros_arch_x86_64::gdt::KERNEL_CODE,
        staros_arch_x86_64::gdt::USER_CODE32 & !3,
    );
    let _ = writeln!(
        console,
        "syscall: enabled, entry {:#x}, kernel cs {:#04x}, sysret cs {:#04x} ss {:#04x}, fmask {:#x}",
        // SAFETY: ring 0; a plain MSR read.
        unsafe { cpu::read_msr(arch_syscall::IA32_LSTAR) },
        arch_syscall::syscall_cs(star),
        arch_syscall::sysret_cs(star),
        arch_syscall::sysret_ss(star),
        arch_syscall::FMASK,
    );
    let _ = writeln!(
        console,
        "user: {blob_len} byte program at {USER_CODE:#x} r-x, stack {USER_STACK:#x} rw-, \
         clock {USER_CLOCK:#x} r--"
    );
    Ok(())
}

/// The task body for the ring-3 program: drop into it and never come back.
///
/// A kernel thread whose whole job is one instruction. Its kernel stack is what
/// the scheduler installed in `TSS.rsp0` and in the per-core block when it
/// switched here, and this function's own frame is abandoned the moment `iretq`
/// runs — which is correct, because a task in ring 3 has an empty kernel stack by
/// definition, and every way back in starts at the top of it.
extern "C" fn user_task() {
    // SAFETY: `init` mapped executable code at `USER_CODE` and a writable stack
    // below `USER_STACK_TOP`, both user-accessible in the live tree; the IDT is
    // installed, `syscall` is enabled and its handler registered, and the
    // scheduler set this task's kernel stack in `TSS.rsp0` when it switched here.
    unsafe { usermode::enter_ring3(USER_CODE, USER_STACK_TOP) }
}

/// Every syscall arrives here.
fn on_syscall(frame: &mut SyscallFrame) {
    SYSCALLS.fetch_add(1, Ordering::Relaxed);

    // Armed *before* the call is served, and consumed here, so the corruption
    // lands on a return the program would otherwise have made successfully. See
    // `selftest_noncanonical`.
    let corrupt = ARM_NONCANONICAL.swap(false, Ordering::SeqCst);

    match Syscall::from_raw(frame.rax as usize) {
        Some(Syscall::Yield) => {
            frame.rax = 0;
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
            // Down through the scheduler and back. The frame stays on this task's
            // kernel stack while another task runs on its own — and `GS` is a
            // property of the *core*, not of this task, so it has to be put back
            // the way ordinary ring-0 code expects it before anything else runs.
            // SAFETY: ring 0, inside the syscall path, and paired with the second
            // call below. See `arch_syscall::swap_gs`.
            unsafe { arch_syscall::swap_gs() };
            sched::yield_now();
            // SAFETY: the pairing. This task is on the CPU again and about to
            // return through the stub, which expects the kernel base in `GS`.
            unsafe { arch_syscall::swap_gs() };
        }
        Some(Syscall::Exit) => {
            // Never returns, and never writes `rax`: there is nobody left to read
            // it. The trap frame on this stack is abandoned along with the stack.
            //
            // The unpaired half of the stub's `swapgs` is exactly why this call is
            // here: the exit path of the stub is what would have restored `GS`,
            // and this task will never reach it.
            // SAFETY: ring 0, inside the syscall path; this pairs with the stub's
            // entry `swapgs`, which nothing else will now match.
            unsafe { arch_syscall::swap_gs() };
            sched::exit()
        }
        Some(Syscall::DebugWrite) => {
            frame.rax = debug_write(frame.rdi, frame.rsi);
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
        }
        // Defined in the shared ABI, not implemented here. Answering "no such
        // syscall" rather than zero, because a syscall that returns success
        // without doing anything is the one kind of bug user space cannot see.
        _ => {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            frame.rax = KError::NoSuchSyscall.as_raw() as u64;
            if corrupt {
                frame.rip = NONCANONICAL_RIP;
            }
        }
    }
}

/// `DebugWrite`: emit `len` bytes from ring 3's `ptr` as one console message.
///
/// Returns the number of bytes written, or a negative [`KError`] as a raw `u64` —
/// which is what the ABI says a syscall result is, and why the caller reads it as
/// a signed value.
fn debug_write(ptr: u64, len: u64) -> u64 {
    let Ok(len) = usize::try_from(len) else {
        return KError::InvalidArgument.as_raw() as u64;
    };
    if len > DEBUG_WRITE_MAX {
        return KError::InvalidArgument.as_raw() as u64;
    }

    let tables = *TABLES.lock();
    let Some(tables) = tables else {
        return KError::NotSupported.as_raw() as u64;
    };
    // The walk, not a range check. An address in the user half proves only that
    // it is not the kernel's: it may be unmapped, or mapped for the kernel alone,
    // and dereferencing either from ring 0 is a `#PF` in the kernel.
    if !vm::user_range_ok(&tables, ptr, len as u64, false) {
        return KError::InvalidArgument.as_raw() as u64;
    }

    let mut buffer = [0u8; DEBUG_WRITE_MAX];
    // The one place in this kernel that opens the SMAP window. `stac` sets
    // `RFLAGS.AC`, which suspends SMAP for supervisor accesses to user pages;
    // `clac` closes it again. The window is exactly as wide as the copy, and the
    // copy is bounded above by `DEBUG_WRITE_MAX`, because the whole point of SMAP
    // is that ring 0 touching user memory should be a deliberate, narrow act.
    //
    // Conditional, and not as a micro-optimisation: on a CPU without SMAP `stac`
    // is not a no-op, it is `#UD`. `qemu64` is such a CPU, which is why it is in
    // the boot matrix — the feature the kernel checked for in phase 1.4 and the
    // instruction it uses in 3.1 are the same fact, and using the instruction
    // unconditionally turns "this machine has no SMAP" into an invalid opcode in
    // the middle of a syscall.
    //
    // SAFETY: the range has just been verified mapped and user-readable in the
    // live tree, `len <= DEBUG_WRITE_MAX` bounds the destination, and the two
    // regions cannot overlap (one is a user address, the other this frame's
    // stack). `AC` is restored to clear immediately afterwards, and neither
    // instruction is issued on a machine that does not have SMAP enabled.
    unsafe {
        if tables.smap {
            cpu::stac();
        }
        core::ptr::copy_nonoverlapping(ptr as *const u8, buffer.as_mut_ptr(), len);
        if tables.smap {
            cpu::clac();
        }
    }

    match core::str::from_utf8(&buffer[..len]) {
        Ok(text) => {
            // One `write_str`, so the console lock is held once for the whole of
            // the caller's message — the same guarantee kernel code gets, which is
            // what makes ring-3 output that interleaves with a kernel task's still
            // readable.
            if let Some(mut console) = crate::console::get() {
                let _ = console.write_str(text);
            }
            BYTES_WRITTEN.fetch_add(len as u64, Ordering::Relaxed);
            len as u64
        }
        // Not fatal, and not silently mangled either: the console draws bytes, and
        // a program that hands it a broken sequence should be told so rather than
        // watch half its line appear.
        Err(_) => KError::InvalidArgument.as_raw() as u64,
    }
}

/// Run the ring-3 program alongside a kernel thread, and check what happened.
///
/// The criterion for phase 3.1, and it is four separate claims that the same run
/// happens to establish:
///
/// - **ring 3 executed at all** — its first `DebugWrite` reached the console,
///   which means `iretq` lowered the privilege level, `syscall` was a valid
///   opcode, `IA32_LSTAR` pointed at the stub, and `sysretq` came back.
/// - **the timer interrupted ring 3** — the program's spin loop enters the kernel
///   nowhere, so every tick counted during it arrived from ring 3 and used
///   `TSS.rsp0`. A null there is a `#DF` on the first tick.
/// - **a syscall yielded and the program resumed** — down through `syscall`, out
///   through the scheduler to another task, back, and `sysretq` returned to the
///   instruction after it.
/// - **it exited, and the kernel is still here** — a ring-3 task ending is an
///   ordinary scheduler event, not the end of the boot.
///
/// # Safety
/// Called once, after [`init`], with the timer calibrated.
pub unsafe fn selftest(console: &mut Console) -> bool {
    if !sched::spawn("U", user_task) || !sched::spawn("K", witness) {
        let _ = writeln!(console, "user SELF-TEST FAILED: could not spawn the tasks");
        return false;
    }
    let _ = writeln!(
        console,
        "user: entering ring 3 at {USER_CODE:#x} with rsp {USER_STACK_TOP:#x}, \
         alongside one kernel thread"
    );

    let ticks_before = crate::irq::ticks_from_ring3();
    // SAFETY: the timer is calibrated and its vector is the only unmasked source.
    let Ok(hz) = (unsafe { crate::irq::start_ticking() }) else {
        let _ = writeln!(console, "user SELF-TEST FAILED: the timer would not start");
        return false;
    };

    sched::start();

    // SAFETY: nothing after this expects to be interrupted.
    unsafe { crate::irq::stop_ticking() };

    let from_ring3 = crate::irq::ticks_from_ring3() - ticks_before;
    let syscalls = SYSCALLS.load(Ordering::Relaxed);
    let refused = REFUSED.load(Ordering::Relaxed);
    let written = BYTES_WRITTEN.load(Ordering::Relaxed);
    let (_, preemptions, yields) = sched::switch_counts();

    let _ = writeln!(
        console,
        "user: {syscalls} syscalls served ({refused} refused), {written} bytes written, \
         {yields} voluntary switch(es)"
    );
    let _ = writeln!(
        console,
        "user: {from_ring3} timer interrupts arrived from ring 3 at {hz} Hz \
         (they used TSS.rsp0, nothing else could have)"
    );

    let mut ok = true;
    if written == 0 {
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: ring 3 wrote nothing - it never ran, or `syscall` never arrived"
        );
        ok = false;
    }
    if from_ring3 == 0 {
        // The one that only ring 3 can demonstrate. A kernel thread being
        // preempted proves nothing about `rsp0`: the CPU changes no stack when the
        // privilege level does not change.
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: no interrupt arrived while ring 3 was executing"
        );
        ok = false;
    }
    if yields == 0 {
        let _ = writeln!(
            console,
            "user SELF-TEST FAILED: no task yielded - the `Yield` syscall did not reach the scheduler"
        );
        ok = false;
    }
    if preemptions == 0 {
        let _ = writeln!(console, "user SELF-TEST FAILED: nothing was preempted");
        ok = false;
    }
    if refused != 0 {
        let _ = writeln!(console, "user SELF-TEST FAILED: {refused} syscall(s) were not understood");
        ok = false;
    }
    ok
}

/// A kernel thread to share the CPU with the ring-3 program.
///
/// Its only purpose is to be *something else to switch to*, so that the ring-3
/// task's `Yield` has somewhere to go and its preemptions are real switches rather
/// than a reschedule that picks the same task again. It says nothing: two writers
/// were phase 2.4's demonstration, and here the interleaving would only obscure
/// the ring-3 output that is the point.
extern "C" fn witness() {
    let start = crate::irq::ticks();
    while crate::irq::ticks().saturating_sub(start) < USER_RUN_TICKS + 5 {
        core::hint::spin_loop();
    }
}

/// Force one non-canonical return address and check where the fault lands.
///
/// The hazard the roadmap names, and it is a privilege escalation rather than a
/// crash. `sysretq` takes `RIP` from `RCX` and raises `#GP` if it is
/// non-canonical — **before** the drop to ring 3, so the fault is delivered in
/// ring 0, on the kernel stack, with the kernel's `CS`. Ring 3 choosing where the
/// kernel faults is not a bug class anybody wants to be in.
///
/// So the arch crate checks [`staros_arch_x86_64::syscall::is_canonical`] on the
/// way out and returns through `iretq` instead, which handles any `RIP` and
/// delivers the `#GP` in ring 3 — where the trap handler kills the task that
/// caused it and the boot carries on.
///
/// The corruption is the kernel's own doing, deliberately: a ring-3 program cannot
/// easily arrange a non-canonical `RCX` for itself, because `syscall` overwrites
/// `RCX` with a return address that is canonical by construction. The realistic
/// route is a kernel that *modifies* the saved return address — which is exactly
/// what this does, in one place, under a flag.
///
/// # Safety
/// Called once, after [`selftest`], with the timer calibrated.
pub unsafe fn selftest_noncanonical(console: &mut Console) -> bool {
    let faults_before = user_faults();
    ARM_NONCANONICAL.store(true, Ordering::SeqCst);

    if !sched::spawn("N", user_task) {
        let _ = writeln!(console, "sysret SELF-TEST FAILED: could not spawn the task");
        return false;
    }
    let _ = writeln!(
        console,
        "sysret: forcing a non-canonical return address ({NONCANONICAL_RIP:#x}) \
         on the program's first syscall"
    );

    // SAFETY: as `selftest`. The timer runs so the task is schedulable in the
    // ordinary way; it is not expected to survive long enough to be preempted.
    let _ = unsafe { crate::irq::start_ticking() };
    sched::start();
    // SAFETY: nothing after this expects to be interrupted.
    unsafe { crate::irq::stop_ticking() };

    ARM_NONCANONICAL.store(false, Ordering::SeqCst);
    let faults = user_faults() - faults_before;
    let irets = arch_syscall::iret_returns();

    if faults == 0 {
        let _ = writeln!(
            console,
            "sysret SELF-TEST FAILED: the corrupted return address caused no fault at all"
        );
        return false;
    }
    // The assertion that makes the mitigation falsifiable, which the fault above
    // does not. On this emulator — and on any AMD part — `sysretq` does not check
    // the address at all: it loads it and the fetch faults in ring 3, which is
    // exactly what the check produces anyway. The two are distinguishable only on
    // Intel silicon, where the unchecked path faults in *ring 0*. So the boot
    // asserts on the decision rather than on its consequence: one return went out
    // the slow way, and that is false the moment the check is removed.
    if irets == 0 {
        let _ = writeln!(
            console,
            "sysret SELF-TEST FAILED: the return took `sysretq` with a non-canonical address - \
             on Intel that #GP is delivered in ring 0"
        );
        return false;
    }
    let _ = writeln!(
        console,
        "sysret: {irets} return(s) went out through iretq instead; the fault arrived in ring 3 \
         and killed only that task"
    );
    true
}
