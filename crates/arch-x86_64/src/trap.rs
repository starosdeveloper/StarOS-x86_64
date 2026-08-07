//! Exception and interrupt entry: 256 stubs, one saved frame, one dispatcher.
//!
//! This is the structural difference from the aarch64 tree, and it is worth
//! naming precisely. There, `VBAR_EL1` has sixteen entries selected by the
//! *class* of exception, and what actually happened is decoded afterwards from
//! `ESR_EL1`. Here the vector number *is* the answer: 256 separate entry points,
//! and the CPU picks one. So the table is generated rather than written.
//!
//! ## Why the stubs are assembly and why they are uniform
//! Ten vectors push an error code and the rest do not, so the stack frame the
//! handler sees has two possible shapes. Rather than teach the handler about
//! both, every stub without an error code pushes a zero in its place. From that
//! point on there is exactly one frame layout, [`TrapFrame`], and it is `repr(C)`
//! with its fields in the order the pushes leave them in memory.
//!
//! That uniformity is also what makes the alignment work out. In 64-bit mode the
//! CPU aligns `RSP` to sixteen before pushing its five words. With the dummy
//! error code the stubs always add two more, and the common path adds fifteen
//! register saves: 5 + 2 + 15 = 22 words = 176 bytes, and 176 is a multiple of
//! sixteen. So `RSP` is 16-byte aligned at the `call`, which is what the System V
//! ABI requires and what SSE spills assume. Dropping the dummy push would break
//! it for half the vectors and the symptom would be a misaligned fault inside
//! the *reporting* code.
//!
//! ## What is deliberately absent
//! No `swapgs`, because there is no user space yet and `GS` base is unused; a
//! `swapgs` on entry from ring 0 would swap in garbage. No FPU or SSE state
//! save, because the kernel is built with SSE disabled. Both belong to phase 2,
//! with the ring transition that makes them necessary.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The machine state at the moment of a trap, as the stubs lay it out.
///
/// Field order is the ABI here, exactly as in `efi.rs`: it is the memory the
/// stub built with a sequence of pushes, and the last thing pushed is `rax` at
/// the lowest address. Reordering any field silently reinterprets a register as
/// another one.
///
/// A handler may modify any field. Everything below `vector` is restored by
/// `iretq` on the way out, so writing [`TrapFrame::rip`] resumes somewhere else —
/// which is how the fault self-test steps over the instruction that faulted.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapFrame {
    /// Saved general-purpose registers, in push order.
    pub rax: u64,
    /// Saved `RBX`.
    pub rbx: u64,
    /// Saved `RCX`.
    pub rcx: u64,
    /// Saved `RDX`.
    pub rdx: u64,
    /// Saved `RSI`.
    pub rsi: u64,
    /// Saved `RDI`.
    pub rdi: u64,
    /// Saved `RBP`.
    pub rbp: u64,
    /// Saved `R8`.
    pub r8: u64,
    /// Saved `R9`.
    pub r9: u64,
    /// Saved `R10`.
    pub r10: u64,
    /// Saved `R11`.
    pub r11: u64,
    /// Saved `R12`.
    pub r12: u64,
    /// Saved `R13`.
    pub r13: u64,
    /// Saved `R14`.
    pub r14: u64,
    /// Saved `R15`.
    pub r15: u64,
    /// Which of the 256 entry points ran. Pushed by the stub.
    pub vector: u64,
    /// The CPU's error code, or zero for the vectors that have none.
    pub error_code: u64,
    /// Address of the faulting or interrupted instruction.
    pub rip: u64,
    /// Code segment selector at the time of the trap.
    pub cs: u64,
    /// Flags at the time of the trap.
    pub rflags: u64,
    /// Stack pointer at the time of the trap. Always pushed in 64-bit mode, even
    /// without a privilege change — unlike 32-bit protected mode.
    pub rsp: u64,
    /// Stack segment selector at the time of the trap.
    pub ss: u64,
}

impl TrapFrame {
    /// Whether the trap came from ring 3, from the bottom two bits of `CS`.
    #[must_use]
    pub const fn from_user(&self) -> bool {
        self.cs & 3 != 0
    }
}

/// The ten vectors on which the CPU pushes an error code.
///
/// Kept here as data so it can be asserted against; the stub generator below
/// repeats the same list in assembler, because the assembler cannot read this
/// one. The pairing is verified at runtime rather than at compile time: the boot
/// self-test takes a `#PF` (vector 14, with an error code) and an `int3`
/// (vector 3, without), and a mismatch in either direction shows up immediately
/// as a wrong [`TrapFrame::vector`].
pub const HAS_ERROR_CODE: [u8; 10] = [8, 10, 11, 12, 13, 14, 17, 21, 29, 30];

/// Whether the CPU pushes an error code for `vector`.
#[must_use]
pub const fn pushes_error_code(vector: u8) -> bool {
    let mut i = 0;
    while i < HAS_ERROR_CODE.len() {
        if HAS_ERROR_CODE[i] == vector {
            return true;
        }
        i += 1;
    }
    false
}

/// The architecture's name for a vector, for reports.
///
/// Vectors 32 and up are whatever the interrupt controller was told to send
/// there; until the APIC is configured in phase 1.5, one arriving is itself the
/// bug being reported.
#[must_use]
pub const fn vector_name(vector: u64) -> &'static str {
    match vector {
        0 => "#DE divide error",
        1 => "#DB debug",
        2 => "NMI",
        3 => "#BP breakpoint",
        4 => "#OF overflow",
        5 => "#BR bound range exceeded",
        6 => "#UD invalid opcode",
        7 => "#NM device not available",
        8 => "#DF double fault",
        10 => "#TS invalid TSS",
        11 => "#NP segment not present",
        12 => "#SS stack-segment fault",
        13 => "#GP general protection fault",
        14 => "#PF page fault",
        16 => "#MF x87 floating-point error",
        17 => "#AC alignment check",
        18 => "#MC machine check",
        19 => "#XM SIMD floating-point error",
        20 => "#VE virtualisation exception",
        21 => "#CP control protection",
        28 => "#HV hypervisor injection",
        29 => "#VC VMM communication",
        30 => "#SX security exception",
        9 | 15 | 22..=27 | 31 => "reserved",
        _ => "external interrupt",
    }
}

/// A decoded `#PF` error code.
///
/// Five bits, and each one changes what the fault means: the same faulting
/// address is a bug in different code depending on whether it was a read or a
/// write, and whether it came from ring 3. Decoded here so the report says what
/// happened rather than printing a number to be looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFaultCause {
    /// The page was present, so this is a permission violation rather than a
    /// missing mapping.
    pub protection_violation: bool,
    /// The access was a write.
    pub write: bool,
    /// The access came from ring 3.
    pub user: bool,
    /// A reserved bit was set in a page-table entry on the walk.
    pub reserved_bit: bool,
    /// The access was an instruction fetch. Only reported when `EFER.NXE` is on,
    /// which the loader sets before it switches to its own tables.
    pub instruction_fetch: bool,
}

impl PageFaultCause {
    /// Decode a `#PF` error code.
    #[must_use]
    pub const fn from_error_code(code: u64) -> Self {
        Self {
            protection_violation: code & (1 << 0) != 0,
            write: code & (1 << 1) != 0,
            user: code & (1 << 2) != 0,
            reserved_bit: code & (1 << 3) != 0,
            instruction_fetch: code & (1 << 4) != 0,
        }
    }

    /// A one-line summary, for a fault report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        // Ordered by what explains the fault best, not by bit number: a reserved
        // bit means the page tables themselves are malformed, which subsumes
        // every other reading of the same code.
        if self.reserved_bit {
            return "reserved bit set in a page-table entry";
        }
        match (self.protection_violation, self.instruction_fetch, self.write, self.user) {
            (false, true, _, _) => "instruction fetch from an unmapped page",
            (false, _, true, _) => "write to an unmapped page",
            (false, _, false, _) => "read from an unmapped page",
            (true, true, _, _) => "instruction fetch from a no-execute page",
            (true, _, true, _) => "write to a read-only page",
            (true, _, false, true) => "user read of a supervisor page",
            (true, _, false, false) => "supervisor read of a page it may not read",
        }
    }
}

/// Signature of the kernel-side trap handler.
pub type Handler = fn(&mut TrapFrame);

/// The installed handler, as a raw function pointer. Zero means none.
static HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Install the function every trap is reported to.
///
/// Not `unsafe`: the pointer comes from a safe `fn` item, and the only thing the
/// dispatcher does with it is call it with a valid frame.
pub fn set_handler(handler: Handler) {
    HANDLER.store(handler as usize, Ordering::SeqCst);
}

/// Called from the common stub with a pointer to the saved frame.
///
/// # Safety
/// Called only by the assembly below, with `frame` pointing at the [`TrapFrame`]
/// it just built on the current stack.
#[cfg(not(test))]
#[no_mangle]
unsafe extern "C" fn staros_trap_dispatch(frame: *mut TrapFrame) {
    let handler = HANDLER.load(Ordering::SeqCst);
    if handler == 0 {
        // Nothing has registered yet, which means a trap arrived between `lidt`
        // and the kernel installing its reporter. There is nowhere to print, so
        // stopping is the only thing left that is not a lie.
        crate::cpu::halt()
    }
    // SAFETY: `handler` was stored from a `Handler` fn item by `set_handler` and
    // is never stored from anywhere else, so the transmute reverses exactly the
    // cast that produced it.
    let handler: Handler = unsafe { core::mem::transmute::<usize, Handler>(handler) };
    // SAFETY: the caller guarantees the pointer is the live frame; no other code
    // holds a reference to it while this call runs.
    handler(unsafe { &mut *frame });
}

/// The address of each of the 256 stubs, in vector order.
///
/// # Safety
/// Reads a table the assembler emitted below, whose length is fixed at 256.
#[cfg(not(test))]
#[must_use]
pub fn stub_table() -> &'static [u64; 256] {
    unsafe extern "C" {
        static staros_trap_stubs: [u64; 256];
    }
    // SAFETY: the symbol is defined immediately below with exactly this type and
    // is `.rodata`, so nothing ever writes to it.
    unsafe { &staros_trap_stubs }
}

// The stubs themselves. Generated by the assembler rather than by a Rust macro
// because 256 `naked` functions is 256 items for the compiler to inline-decide
// about, and because the address table has to be contiguous and in vector order:
// here that is a `.rept` over `.quad`, which cannot get out of step with the
// stubs it points at.
//
// `.altmacro` is what allows the loop counter to be pasted into a label name.
// It is turned off again at the end, since it changes how `%` is parsed for
// everything that follows in the same file.
#[cfg(not(test))]
core::arch::global_asm!(
    r#"
.section .text
.altmacro

.macro STAROS_TRAP_STUB vec
.globl staros_trap_stub_\vec
staros_trap_stub_\vec:
.if (\vec==8)||(\vec==10)||(\vec==11)||(\vec==12)||(\vec==13)||(\vec==14)||(\vec==17)||(\vec==21)||(\vec==29)||(\vec==30)
    /* The CPU already pushed an error code. Leave it in place. */
.else
    push 0
.endif
    push \vec
    jmp staros_trap_common
.endm

.set staros_vec, 0
.rept 256
    STAROS_TRAP_STUB %staros_vec
    .set staros_vec, staros_vec+1
.endr

staros_trap_common:
    /* Pushed high address first, so `rax` ends up at the lowest address and the
       whole block matches TrapFrame's field order. */
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax
    /* The System V ABI says compiled code may assume DF is clear on entry, and
       an interrupt can land on any instruction — including one inside a `std`
       sequence. Clearing it here costs one byte. */
    cld
    mov rdi, rsp
    call staros_trap_dispatch
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    /* Drop the vector and the error code — real or synthesised, `iretq` wants
       neither. */
    add rsp, 16
    iretq

.macro STAROS_TRAP_PTR vec
    .quad staros_trap_stub_\vec
.endm

.section .rodata
.globl staros_trap_stubs
staros_trap_stubs:
.set staros_vec, 0
.rept 256
    STAROS_TRAP_PTR %staros_vec
    .set staros_vec, staros_vec+1
.endr

.noaltmacro
.section .text
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_is_the_layout_the_stubs_build() {
        // 22 words: 15 saved registers, the vector, the error code, and the five
        // the CPU pushes. If this changes, the assembly above must change with
        // it — and the alignment argument in the module documentation has to be
        // redone, because it depends on the total being a multiple of 16.
        assert_eq!(size_of::<TrapFrame>(), 22 * 8);
        assert_eq!(size_of::<TrapFrame>() % 16, 0, "the call in the stub would be misaligned");
    }

    #[test]
    fn frame_fields_sit_where_the_pushes_put_them() {
        let f = TrapFrame {
            rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rbp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
            vector: 0, error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
        };
        let base = &f as *const TrapFrame as usize;
        let at = |p: *const u64| (p as usize - base) / 8;
        // The four that matter to a report, and the two the stub itself pushes.
        assert_eq!(at(&f.rax), 0, "rax is pushed last, so it is at the lowest address");
        assert_eq!(at(&f.r15), 14);
        assert_eq!(at(&f.vector), 15);
        assert_eq!(at(&f.error_code), 16);
        assert_eq!(at(&f.rip), 17, "the CPU's frame starts here");
        assert_eq!(at(&f.ss), 21);
    }

    #[test]
    fn error_code_vectors_are_the_architecture_list() {
        // Not a restatement of the constant: a sweep of all 256 vectors against
        // an independently written predicate.
        for v in 0u8..=255 {
            let expected = matches!(v, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30);
            assert_eq!(pushes_error_code(v), expected, "vector {v}");
        }
    }

    #[test]
    fn every_vector_has_a_name() {
        for v in 0u64..256 {
            assert!(!vector_name(v).is_empty(), "vector {v}");
        }
        assert_eq!(vector_name(14), "#PF page fault");
        assert_eq!(vector_name(8), "#DF double fault");
        assert_eq!(vector_name(255), "external interrupt");
    }

    #[test]
    fn page_fault_bits_decode_to_the_right_bits() {
        let c = PageFaultCause::from_error_code(0b1_1111);
        assert!(c.protection_violation && c.write && c.user && c.reserved_bit && c.instruction_fetch);
        let c = PageFaultCause::from_error_code(0);
        assert!(!c.protection_violation && !c.write && !c.user);
        // Bits above 4 are not ours to interpret and must not leak into any of
        // the five.
        let c = PageFaultCause::from_error_code(0xFFFF_FFFF_FFFF_FFE0);
        assert_eq!(c, PageFaultCause::from_error_code(0));
    }

    #[test]
    fn page_fault_summaries_distinguish_the_cases_that_matter() {
        // A null read: no page there, not a permission problem. This is the
        // exact code the boot self-test produces, and the wording it prints.
        let read_unmapped = PageFaultCause::from_error_code(0);
        assert_eq!(read_unmapped.as_str(), "read from an unmapped page");
        // A kernel stack overflow onto the guard page: a write, not present.
        let write_unmapped = PageFaultCause::from_error_code(0b10);
        assert_eq!(write_unmapped.as_str(), "write to an unmapped page");
        // W^X doing its job: an instruction fetch from a present NX page.
        let nx = PageFaultCause::from_error_code(0b1_0001);
        assert_eq!(nx.as_str(), "instruction fetch from a no-execute page");
        // A write to a page mapped read-only, e.g. the kernel's own .rodata.
        let ro = PageFaultCause::from_error_code(0b11);
        assert_eq!(ro.as_str(), "write to a read-only page");
        // Malformed tables win over every other reading of the same code.
        let reserved = PageFaultCause::from_error_code(0b1_1111);
        assert_eq!(reserved.as_str(), "reserved bit set in a page-table entry");
    }

    #[test]
    fn ring_is_read_from_the_bottom_of_cs() {
        let mut f = TrapFrame {
            rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rbp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
            vector: 0, error_code: 0, rip: 0, cs: 0x08, rflags: 0, rsp: 0, ss: 0,
        };
        assert!(!f.from_user());
        f.cs = 0x28 | 3;
        assert!(f.from_user());
    }
}
