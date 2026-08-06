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
//! - [`cpu`] — halting and interrupt masking.
//!
//! Everything else the port needs — GDT, IDT, paging, APIC, SMP, syscall entry —
//! is scheduled in `docs/ROADMAP.md` and specified in `docs/SPEC.md`. They are
//! listed there rather than stubbed here: an empty function that returns `Ok`
//! is worse than an absent one, because the boot log then claims a subsystem
//! came up.

#![no_std]

pub mod cpu;
pub mod port;
pub mod serial;
