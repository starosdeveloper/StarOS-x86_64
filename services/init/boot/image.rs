//! The ring-3 boot image — the first user program, as a *separately compiled*
//! x86-64 binary the kernel loads at runtime.
//!
//! Deliberately **not** part of the Cargo workspace build. The kernel's
//! `build.rs` compiles this one file with a plain `rustc` invocation using
//! [`image.ld`](image.ld), which links it at `USER_BASE` = 0x400000 with separate
//! read-execute and read-write `PT_LOAD` segments. The kernel `include_bytes!`s
//! the resulting **ELF** and `staros-elf64` — the same parser the UEFI loader uses
//! on the kernel itself — walks its program headers, so what runs in ring 3 is a
//! real, independently linked executable rather than assembly baked into the
//! kernel's own `.text`.
//!
//! Phase 3.1 could not do that: it had a blob assembled into `.rodata` and copied
//! into a frame, because there was no per-task address space to load anything
//! into. This file is what replaces it.
//!
//! ## What the program does
//! It branches on **its own process id**, a single byte the kernel seeds at
//! `USER_DATA_VA` (0x4_0000_0000) — a different physical page for each task, at
//! the same virtual address. That branch is the demonstration:
//!
//! - **id 1** prints, writes into its own read/write segment, checks that its
//!   `.bss` really arrived zeroed, spins in ring 3 until the kernel's clock has
//!   advanced, prints again to say it outlived its neighbour, and exits cleanly.
//! - **id 2** prints and then dereferences a null pointer, which is a `#PF` in
//!   ring 3. It should die and take nothing else with it.
//!
//! Both are the same image at the same address. The only thing that differs is
//! the page underneath.
//!
//! ## Why it is one naked function
//! No runtime, no relocations, no `core` memory intrinsics — so the pre-compiled
//! `core` for an ordinary target is enough and the build needs no `-Zbuild-std`.
//! Its only inputs are the syscall numbers (which must match
//! `staros_abi::syscall::Syscall`) and the two addresses the kernel seeds.
//!
//! Syscall numbers: `Yield` = 0, `Exit` = 4, `DebugWrite` = 19.

#![no_std]
#![no_main]

use core::arch::naked_asm;
use core::panic::PanicInfo;

/// Entry point. Linked and loaded at 0x400000 and named by `e_entry`, so the
/// kernel's `iretq` lands straight on its first instruction.
///
/// The System V syscall convention: number in `RAX`, arguments in `RDI`, `RSI`,
/// `RDX`, `R10`, `R8`, `R9`, result in `RAX`. `RCX` and `R11` are destroyed by
/// the instruction, which is why `R10` is the fourth argument and why nothing
/// here keeps anything in either across a call.
#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text.start"]
extern "C" fn _start() -> ! {
    naked_asm!(
        // The per-process id, sixteen gigabytes above the image. A different
        // frame per task at the same virtual address — the whole point.
        "mov    r15, 0x400000000",
        "movzx  r14d, byte ptr [r15]",

        // Stamp the id into the message. The message lives in `.data`, so this
        // write only succeeds if the loader mapped the second segment writable —
        // and it is a *private* copy, so the two tasks do not overwrite each
        // other's digit.
        "lea    rdi, [rip + staros_user_msg_running]",
        "lea    eax, [r14 + 48]",           // '0' + id
        "mov    byte ptr [rdi + 5], al",

        "cmp    r14d, 1",
        "jne    .Ltask_two",

        // ---- id 1: the task that survives -------------------------------
        "call   .Lputs",

        // `.bss` must have arrived zeroed. p_memsz exceeds p_filesz for the
        // writable segment, and nothing but this checks that the loader zeroed
        // the tail rather than handing over whatever the frame last held.
        "lea    rax, [rip + staros_user_bss_probe]",
        "mov    rax, [rax]",
        "test   rax, rax",
        "jz     2f",
        "lea    rdi, [rip + staros_user_msg_dirty_bss]",
        "call   .Lputs",
        "jmp    .Lexit",
    "2:",

        // Spin in ring 3 until the kernel's clock has moved. Nothing here enters
        // the kernel, so every tick that lands during this loop is an interrupt
        // taken from ring 3 — which needs TSS.rsp0 and a per-task kernel stack.
        "mov    r12, 0x400010000",
        "mov    r13, [r12]",
        "add    r13, 30",
    "3:",
        "mov    rax, [r12]",
        "cmp    rax, r13",
        "jb     3b",

        // Give the CPU up once on purpose, then say we are still here. By now
        // the other task has faulted and been destroyed.
        "xor    eax, eax",                  // Yield
        "syscall",
        "lea    rdi, [rip + staros_user_msg_survived]",
        "call   .Lputs",
        "jmp    .Lexit",

        // ---- id 2: the task that dies -----------------------------------
    ".Ltask_two:",
        "call   .Lputs",
        "lea    rdi, [rip + staros_user_msg_touching_zero]",
        "call   .Lputs",
        // Address zero is not mapped in this space, and this is ring 3. The
        // kernel must report a page fault, destroy this task, and carry on.
        "xor    eax, eax",
        "mov    rax, [rax]",
        // If that returned, address zero was mapped and the isolation this phase
        // claims does not exist. Fault loudly rather than exit quietly.
        "ud2",

    ".Lexit:",
        "mov    eax, 4",                    // Exit
        "syscall",
        "ud2",

        // ---- helper -------------------------------------------------------
        // Write the NUL-terminated string at RDI as one `DebugWrite`. User space
        // measures its own strings; using `call`/`ret` also proves the stack the
        // kernel mapped is writable.
    ".Lputs:",
        "mov    rsi, rdi",
        "xor    ecx, ecx",
    "4:",
        "cmp    byte ptr [rsi + rcx], 0",
        "je     5f",
        "inc    rcx",
        "jmp    4b",
    "5:",
        "mov    rsi, rcx",
        "mov    eax, 19",                   // DebugWrite
        "syscall",
        "ret",
    )
}

// The program's data, in its own `global_asm!` rather than inside the naked
// function. Switching sections in the middle of a function body is what LLVM
// refuses ("size expression must be absolute"): it is still trying to compute
// how long `_start` is, and a `.bss` label in the middle of it has no answer.
//
// The strings live in `.data` and not `.rodata` on purpose. `_start` stamps the
// process id into one of them, so the program cannot get past its first line
// unless the loader mapped the second segment writable — and it is a *private*
// copy per task, so the two do not overwrite each other's digit.
core::arch::global_asm!(
    r#"
.section .data
.globl staros_user_msg_running
staros_user_msg_running:
    .asciz "user ?: running at 0x400000 in its own address space\n"
.globl staros_user_msg_touching_zero
staros_user_msg_touching_zero:
    .asciz "user 2: dereferencing address zero, which nothing maps here\n"
.globl staros_user_msg_survived
staros_user_msg_survived:
    .asciz "user 1: still running after its neighbour faulted\n"
.globl staros_user_msg_dirty_bss
staros_user_msg_dirty_bss:
    .asciz "user 1: BSS ARRIVED DIRTY - the loader did not zero the tail\n"

/* The only reason p_memsz exceeds p_filesz for the writable segment, and the
   only thing that can tell a loader which zeroes the tail from one that hands
   over whatever the frame last held. Checked by `_start`. */
.section .bss
.globl staros_user_bss_probe
staros_user_bss_probe:
    .zero 8
"#
);

/// Nothing in this program panics — it is one naked function — but `no_std`
/// requires the lang item to exist.
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    // No console without a syscall, and no syscall without registers this
    // handler can be sure of. Spin: the kernel's timer will preempt and the task
    // can be observed as stuck rather than as silently gone.
    loop {
        core::hint::spin_loop();
    }
}
