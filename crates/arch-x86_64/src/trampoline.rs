//! The sixteen-bit code an application processor wakes up in.
//!
//! A core answering a startup message begins in **real mode**, at
//! `page * 0x1000`, with no stack, no paging, no GDT it can trust and 16-bit
//! registers — the machine as it was in 1981, on a CPU that has been running
//! 64-bit code for the last second. Everything the kernel is depends on state
//! this core does not have, so the first thing it executes cannot be Rust.
//!
//! This is the only non-64-bit code in the tree, and it exists to be as short as
//! possible: reach long mode, load the tables the boot processor already built,
//! and call into Rust. Every decision it could make instead belongs on the other
//! side of that call, where there is a compiler.
//!
//! ## How the parameters arrive
//!
//! The blob is copied to a page below 1 MiB, and the values it needs are written
//! into a small block at a **fixed offset** inside that page rather than passed in
//! registers: a core coming out of INIT has no registers worth anything, and the
//! startup message carries eight bits, all of which are the page number. So the
//! contract is spatial — [`ParamOffsets`] names it for both sides, and the
//! assembly reads the same numbers through `const` operands so the two cannot
//! drift.
//!
//! ## Why the code is position-independent within its page
//!
//! It runs at whatever address the page lands on, which the kernel chooses, so
//! every reference is relative to the page base held in a segment register. A
//! `mov` to an absolute label would assemble to the address the linker picked for
//! the kernel image — sixty-four bits away from where these instructions are.

use core::arch::global_asm;

/// Byte offsets of the parameter block, from the start of the trampoline page.
///
/// The parameters sit at the **end** of the page, above the code. Putting them
/// first would be one instruction shorter and would put a jump target inside data
/// the kernel writes — the first mistake in filling this block would then be
/// executed rather than merely read.
pub mod params {
    /// Physical address of the page tables the new core is to adopt (`CR3`).
    pub const CR3: usize = 0xF00;
    /// Top of this core's kernel stack, as a virtual address.
    pub const STACK_TOP: usize = 0xF08;
    /// Virtual address of the Rust function to call once in long mode.
    pub const ENTRY: usize = 0xF10;
    /// The APIC id the kernel expects to answer, written by the kernel and read
    /// back by the core as its first act — see `ACK`.
    pub const CPU_ID: usize = 0xF18;
    /// Set to a non-zero value by the core once it is running 64-bit code with
    /// the kernel's tables loaded.
    ///
    /// This is what "the core came up" means. Without it the boot processor can
    /// only conclude that it *sent* a startup message, which is not the same
    /// claim and is true on a machine where nothing answered.
    pub const ACK: usize = 0xF20;
}

/// Where the blob's parameter block begins. The assembly is written against this
/// and the kernel fills it in at these offsets.
pub const PARAM_BASE: usize = params::CR3;

unsafe extern "C" {
    /// First byte of the trampoline blob, as linked into the kernel image.
    pub static trampoline_start: u8;
    /// One past its last byte.
    pub static trampoline_end: u8;
}

/// How many bytes of the blob must be copied to the low page.
///
/// # Safety
/// Reads two linker-provided symbols; both are addresses within the kernel image.
#[must_use]
pub fn blob_len() -> usize {
    let start = &raw const trampoline_start as usize;
    let end = &raw const trampoline_end as usize;
    end - start
}

global_asm!(
    ".section .rodata.trampoline, \"a\"",
    ".balign 4096",
    ".code16",
    ".globl trampoline_start",
    "trampoline_start:",

    // Real mode, no stack, nothing to rely on. `CS` holds the page this code was
    // started at, so it is the only pointer available — every reference below is
    // built from it.
    "cli",
    "cld",
    "xor ax, ax",
    "mov ds, ax",
    "mov es, ax",
    "mov ss, ax",

    // The page base as a linear address: CS is the page number, so CS << 4.
    "mov ax, cs",
    "movzx ebx, ax",
    "shl ebx, 4",              // ebx = physical base of this page

    // Load a GDT that describes 32-bit code, built here rather than borrowed:
    // the kernel's GDT lives above 4 GiB in virtual space and this core cannot
    // address it yet.
    //
    // Every label is used through a `.set` offset from the start of the blob, not
    // as a symbol. The assembler will not put a difference of two symbols inside a
    // memory operand, and it is right to refuse: the value wanted here is a
    // *distance*, and writing it as an address that happens to be relocated the
    // same way is how position-independent code stops being position-independent.
    //
    // And the distances are taken with `offset`, which in this dialect is what
    // makes a symbol an immediate. Without it `add eax, OFF_GDT32` assembles to
    // `add eax, [0xc0]` — a *load from* the offset instead of an add *of* it. The
    // value is right there in the encoding, so the code looks correct in the
    // source and reads memory that happens to be the interrupt vector table. The
    // far-jump target then stays zero, the jump goes to 0x08:0x00000000, and the
    // core takes a #GP with selector 8 before it has an IDT: `v=0d e=0008`, then
    // `v=08`, then the machine is gone.
    "mov eax, ebx",
    "add eax, offset OFF_GDT32",
    "mov [bx + OFF_GDT32_PTR_BASE], eax",
    "lgdt [bx + OFF_GDT32_PTR]",

    // The jump target is computed **before** protected mode is entered, and that
    // order is the whole of a bug this cost an afternoon.
    //
    // The linker's idea of `protected` is an address in the kernel image, sixty-
    // four bits away from the page these instructions were copied to, so the
    // target has to be built from the page base at run time. Doing that *after*
    // setting CR0.PE stores through `ds`, which still holds the real-mode value 0
    // — and in protected mode selector 0 is the null descriptor. The store takes
    // a #GP, the #GP has no IDT to go to, and the machine triple-faults with
    // nothing on the console. QEMU said it plainly once asked:
    // `v=0d e=0008 pc=0x803d`, then `v=08`, then reset.
    "mov eax, ebx",
    "add eax, offset OFF_PROTECTED",
    "mov [bx + OFF_FAR_JUMP], eax",

    // Protected mode. The far jump is not optional: it is what reloads CS with a
    // descriptor from the new table, and until it happens the CPU is executing
    // 32-bit-enabled code through a 16-bit segment.
    "mov eax, cr0",
    "or eax, 1",
    "mov cr0, eax",
    ".byte 0x66, 0xEA",        // ljmp far, 32-bit operand
    "far_jump_target: .long 0",
    ".word 0x08",              // selector: the 32-bit code descriptor

    ".code32",
    "protected:",
    "mov ax, 0x10",            // the 32-bit data descriptor
    "mov ds, ax",
    "mov es, ax",
    "mov ss, ax",

    // Paging off, long mode not yet on. Enable PAE, adopt the kernel's tables,
    // set the long-mode bit, then turn paging on — in that order, because the CPU
    // only checks the combination when paging is enabled.
    "mov eax, cr4",
    "or eax, 1 << 5",          // CR4.PAE
    "mov cr4, eax",

    "mov eax, [ebx + {off_cr3}]",
    "mov cr3, eax",

    // EFER: long mode *and* no-execute.
    //
    // `NXE` is not optional here even though nothing on this path executes from a
    // data page. The kernel's tables were built by a core that had it on, so they
    // carry bit 63 on every non-executable mapping — and with `NXE` off that bit
    // is **reserved**, not ignored. The first write through such a mapping faults
    // with `RSVD` set, which is what the trace said: `v=0e e=000a` at the `call`
    // that pushes a return address onto a stack the linear map provides. A core
    // that reached long mode and then died on its first push looks like a broken
    // stack pointer, and the stack pointer was fine.
    "mov ecx, 0xC0000080",     // IA32_EFER
    "rdmsr",
    "or eax, 1 << 8",          // EFER.LME
    "or eax, 1 << 11",         // EFER.NXE
    "wrmsr",

    "mov eax, cr0",
    "or eax, 1 << 31",         // CR0.PG — long mode begins here
    "or eax, 1 << 16",         // CR0.WP, so the kernel's read-only pages are read-only
    "mov cr0, eax",

    // A second far jump, into a 64-bit descriptor. Between the two the core is in
    // *compatibility* mode: long mode is active but the code segment still says
    // 32-bit, and the difference is invisible until an instruction encodes a
    // 64-bit register.
    "mov eax, ebx",
    "add eax, offset OFF_LONG_MODE",
    "mov [ebx + OFF_FAR_JUMP64], eax",
    ".byte 0xEA",
    "far_jump64_target: .long 0",
    ".word 0x18",              // selector: the 64-bit code descriptor

    ".code64",
    "long_mode:",
    // The kernel's tables are live, so the parameter block is reachable at its
    // physical address only because the boot processor identity-mapped this page.
    // That mapping is removed once every core has acknowledged.
    "mov rsp, [rbx + {off_stack}]",
    "xor rbp, rbp",
    // Say so before calling anything: the acknowledgement means "this core reached
    // 64-bit code with the kernel's tables", which is exactly the claim that can be
    // made here and not one instruction earlier.
    "mov qword ptr [rbx + {off_ack}], 1",
    "mov rdi, [rbx + {off_cpu_id}]",
    "mov rax, [rbx + {off_entry}]",
    "call rax",
    // The entry point does not return. If it does, stop this core rather than let
    // it run off the end of the page into whatever the kernel put after it.
    "cli",
    "2: hlt",
    "jmp 2b",

    // ---- the temporary descriptor table -------------------------------------
    ".balign 8",
    "gdt32:",
    ".quad 0",                                  // null
    ".quad 0x00CF9A000000FFFF",                 // 0x08: 32-bit code, base 0, 4 GiB
    ".quad 0x00CF92000000FFFF",                 // 0x10: 32-bit data, base 0, 4 GiB
    ".quad 0x00AF9A000000FFFF",                 // 0x18: 64-bit code (L=1)
    "gdt32_ptr:",
    ".word 4 * 8 - 1",
    "gdt32_ptr_base: .long 0",

    ".globl trampoline_end",
    "trampoline_end:",

    // Distances from the start of the blob, resolved by the assembler and used as
    // plain numbers above. They are declared after the labels because a `.set` of
    // a forward difference is not something every assembler will fold.
    ".set OFF_GDT32, gdt32 - trampoline_start",
    ".set OFF_GDT32_PTR, gdt32_ptr - trampoline_start",
    ".set OFF_GDT32_PTR_BASE, gdt32_ptr_base - trampoline_start",
    ".set OFF_PROTECTED, protected - trampoline_start",
    ".set OFF_LONG_MODE, long_mode - trampoline_start",
    ".set OFF_FAR_JUMP, far_jump_target - trampoline_start",
    ".set OFF_FAR_JUMP64, far_jump64_target - trampoline_start",

    off_cr3 = const params::CR3,
    off_stack = const params::STACK_TOP,
    off_entry = const params::ENTRY,
    off_cpu_id = const params::CPU_ID,
    off_ack = const params::ACK,
);
