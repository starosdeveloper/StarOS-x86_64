//! The x86_64 architecture backend.
//!
//! This is the counterpart of `staros-arch-aarch64` in the sibling tree: the one
//! crate allowed to contain architecture-specific `unsafe`, so the portable
//! kernel core never does. What lives here is decided by the same rule — if the
//! code names a register, a port or an instruction, it belongs here; if it
//! reasons about *values*, it belongs in a host-tested crate.
//!
//! ## What is implemented today
//! - [`port`] — the I/O port space, which x86 has and no other architecture does.
//! - [`serial`] — a 16550 UART on the legacy COM1 port, implementing
//!   [`staros_hal::SerialConsole`]. First diagnostic channel, available before
//!   paging, ACPI or interrupts, and the one thing QEMU always gives us.
//! - [`cpu`] — halting, interrupt masking, and the control registers a fault
//!   report needs to read.
//! - [`gdt`] — the descriptor table and the TSS, which is where the interrupt
//!   stacks live.
//! - [`idt`] — the 256 gates, and which of them switch stacks.
//! - [`trap`] — the generated entry stubs, the saved frame, and the dispatcher.
//! - [`pic`] — the two 8259s, which have to be moved off the exception vectors
//!   before any interrupt can be enabled.
//! - [`pit`] — the 8254, in the smallest form that can raise one real hardware
//!   interrupt on demand.
//! - [`mmio`] — memory-mapped registers, as a trait, for the same reason
//!   [`port`] is one.
//! - [`apic`] — the local APIC and the I/O APIC: the controller that replaces
//!   the 8259s, and the place the HAL's interrupt trait had to be reshaped.
//! - [`hpet`] — the one clock on the machine that states its own frequency, and
//!   therefore the ruler every other clock is cut against.
//! - [`context`] — the six callee-saved registers a task switch has to keep, and
//!   the first stack frame a task that has never run needs in order to start.
//! - [`syscall`] — `syscall`/`sysret`: the MSRs that turn the instruction on,
//!   the `swapgs` stack switch x86 needs and AArch64 does not, and the canonical
//!   check without which `sysret` hands ring 3 a fault in ring 0.
//! - [`usermode`] — the five-word frame `iretq` reads to drop into ring 3.
//! - [`selftest`] — faults taken on purpose, because a correct IDT and a subtly
//!   wrong one are both silent until something faults.
//!
//! Everything else the port needs — IPC, the SMP trampoline — is scheduled in
//! `docs/ROADMAP.md` and specified in `docs/SPEC.md`. They are listed there
//! rather than stubbed here: an empty function that returns `Ok` is worse than an
//! absent one, because the boot log then claims a subsystem came up.
//!
//! Per-task address spaces are deliberately *not* here. On aarch64 they are, and
//! for a good reason — `TTBR0`/`TTBR1` is a hardware split, so the code that
//! builds one is architecture-specific by nature. Here the four-level walk lives
//! in the portable, host-tested `staros-paging`, and what remains is policy: which
//! pages a process gets and who frees them. That belongs in the kernel, and it is
//! in `crates/kernel/src/addrspace.rs`.
//!
//! ## Why this crate has host tests
//! Most of it cannot have any — `lgdt` does nothing observable off a CPU. But
//! the *encodings* can, and so can the *sequences*. A descriptor, a gate and a
//! page-fault error code are bit layouts; an 8259 initialisation is eight
//! control words whose meaning is positional. Getting either wrong produces no
//! message at all — a reset, or an interrupt that never arrives. So the layouts
//! are checked against literal values and the sequences against the exact list of
//! port writes, and only the instructions that carry them out are left to the
//! machine.
//!
//! `#![no_std]` is therefore conditional: under `cfg(test)` the crate links
//! against the host's `std` for the harness, and the modules that emit raw
//! assembly are compiled out, since their absolute address tables cannot be
//! relocated into a host PIE.

#![cfg_attr(not(test), no_std)]

pub mod apic;
pub mod context;
pub mod cpu;
pub mod gdt;
pub mod hpet;
pub mod idt;
pub mod mmio;
pub mod pic;
pub mod pit;
pub mod port;
#[cfg(not(test))]
pub mod selftest;
pub mod serial;
pub mod syscall;
pub mod trampoline;
pub mod trap;
#[cfg(not(test))]
pub mod usermode;
