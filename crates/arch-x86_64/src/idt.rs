//! The Interrupt Descriptor Table.
//!
//! 256 sixteen-byte gates, indexed by vector number, each holding a handler
//! address split across three fields for reasons that are purely historical. The
//! interesting bits are the two this kernel actually chooses:
//!
//! - **the gate type.** An *interrupt* gate clears `IF` on entry; a *trap* gate
//!   does not. Every gate here is an interrupt gate, including the ones for
//!   synchronous faults, because a fault report must not be interrupted halfway
//!   through by a device that also wants the console.
//! - **the IST index.** Three bits naming a stack in the TSS, or zero for "keep
//!   using the current one". Only three vectors get one; see [`crate::gdt`] for
//!   why those three.
//!
//! The DPL is 0 on every gate. That is what stops ring 3 from executing `int 14`
//! and handing the kernel a synthetic page fault; when phase 2 introduces user
//! space, `int3` may need DPL 3 for a debugger and nothing else should change.

use core::arch::asm;
use core::mem::size_of;

use crate::gdt::{self, DescriptorTablePointer};
use crate::trap;

/// Number of vectors the architecture defines. Not configurable: the CPU indexes
/// this table with an 8-bit vector.
pub const VECTORS: usize = 256;

/// Present, DPL 0, 64-bit interrupt gate.
const GATE_INTERRUPT: u8 = 0x8E;

/// One IDT gate.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    flags: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl Entry {
    /// A gate the CPU will reject: not present, so a vector that was never
    /// filled in raises `#NP` naming itself rather than jumping to address zero.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            flags: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Build a gate for `handler`, optionally switching to IST slot `ist`.
    ///
    /// `ist` must be 0 (no switch) or 1..=7. Anything else is truncated by the
    /// three-bit field, which would silently select a different stack, so it is
    /// masked here where the mistake is visible.
    #[must_use]
    pub const fn interrupt_gate(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: gdt::KERNEL_CODE,
            ist: ist & 0b111,
            flags: GATE_INTERRUPT,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    /// The handler address, reassembled from the three fields it is split over.
    #[must_use]
    pub const fn handler(&self) -> u64 {
        (self.offset_low as u64) | ((self.offset_mid as u64) << 16) | ((self.offset_high as u64) << 32)
    }

    /// The IST slot this gate selects, or zero.
    #[must_use]
    pub const fn ist(&self) -> u8 {
        self.ist & 0b111
    }
}

/// Which IST slot a vector uses, or zero for "stay on the current stack".
///
/// Three vectors and no more. An IST stack is not re-entrant: it has one fixed
/// top, so a second delivery of the same vector while the first is still running
/// starts writing over the first one's frame. That is acceptable exactly for
/// faults that end the boot anyway, and wrong for anything that returns.
#[must_use]
pub const fn ist_for(vector: usize) -> u8 {
    match vector {
        // The stack is what is broken. Nothing else can be assumed.
        8 => gdt::IST_DOUBLE_FAULT,
        // Arrives at any instruction, including inside another handler's prologue.
        2 => gdt::IST_NMI,
        // The machine is reporting hardware damage; the current stack may be part
        // of the damage.
        18 => gdt::IST_MACHINE_CHECK,
        _ => 0,
    }
}

/// The table, aligned so it never straddles a page boundary needlessly.
#[cfg(not(test))]
#[repr(C, align(16))]
struct Idt([Entry; VECTORS]);

#[cfg(not(test))]
static mut IDT: Idt = Idt([Entry::empty(); VECTORS]);

/// Fill the IDT from the generated stub table and load it.
///
/// From the moment `lidt` retires, a fault is a report instead of a reset. Until
/// then it is neither: it is a triple fault, which on real firmware means the
/// machine restarts with nothing on any console.
///
/// # Safety
/// Called once per core, after [`crate::gdt::install`] — the gates name
/// [`crate::gdt::KERNEL_CODE`], and a gate whose selector is not a valid 64-bit
/// code segment faults on delivery rather than on load.
#[cfg(not(test))]
pub unsafe fn install() {
    let stubs = trap::stub_table();
    let idt = &raw mut IDT;
    for (vector, &stub) in stubs.iter().enumerate() {
        // SAFETY: `IDT` is private to this module with a single writer, and
        // `stubs` has exactly `VECTORS` entries, so `vector` is in range.
        unsafe {
            (*idt).0[vector] = Entry::interrupt_gate(stub, ist_for(vector));
        }
    }

    let pointer = DescriptorTablePointer {
        limit: (size_of::<[Entry; VECTORS]>() - 1) as u16,
        base: idt as u64,
    };
    // SAFETY: `pointer` describes the table just filled, which is a live static;
    // `lidt` only reads through it.
    unsafe {
        asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gate_is_sixteen_bytes() {
        // The CPU indexes the table by `vector * 16`. A padded `Entry` would put
        // every gate but the first at the wrong offset.
        assert_eq!(size_of::<Entry>(), 16);
        assert_eq!(size_of::<[Entry; VECTORS]>(), 4096);
    }

    #[test]
    fn the_handler_address_survives_being_split_in_three() {
        // A distinct byte in every position, so a field written to the wrong
        // place is a wrong value rather than a coincidence.
        let addr = 0xFFFF_FFFF_8012_3456;
        let e = Entry::interrupt_gate(addr, 0);
        assert_eq!(e.handler(), addr);
        assert_eq!(e.offset_low, 0x3456);
        assert_eq!(e.offset_mid, 0x8012);
        assert_eq!(e.offset_high, 0xFFFF_FFFF);
    }

    #[test]
    fn gates_are_present_interrupt_gates_at_dpl_zero() {
        let e = Entry::interrupt_gate(0xFFFF_FFFF_8000_0000, 0);
        assert_eq!(e.flags & 0x80, 0x80, "not present");
        assert_eq!((e.flags >> 5) & 0b11, 0, "DPL is not 0: ring 3 could invoke this");
        assert_eq!(e.flags & 0xF, 0xE, "not a 64-bit interrupt gate");
        // A trap gate (0xF) would leave IF set and let a device interrupt land
        // in the middle of a fault report.
        assert_ne!(e.flags & 0xF, 0xF);
        assert_eq!(e.selector, gdt::KERNEL_CODE);
    }

    #[test]
    fn an_unfilled_gate_is_not_present() {
        // Zero is a valid-looking address. "Not present" is what makes an
        // unfilled vector say so instead of jumping there.
        assert_eq!(Entry::empty().flags & 0x80, 0);
    }

    #[test]
    fn only_the_three_fatal_vectors_take_an_ist() {
        for vector in 0..VECTORS {
            let expected = match vector {
                8 => gdt::IST_DOUBLE_FAULT,
                2 => gdt::IST_NMI,
                18 => gdt::IST_MACHINE_CHECK,
                _ => 0,
            };
            assert_eq!(ist_for(vector), expected, "vector {vector}");
        }
    }

    #[test]
    fn the_ist_field_cannot_spill_into_its_neighbours() {
        // Bits 3..7 of that byte are reserved and must be zero; a value above 7
        // would otherwise set them and the CPU faults on delivery.
        let e = Entry::interrupt_gate(0, 0xFF);
        assert_eq!(e.ist, 0b111);
        assert_eq!(e.ist(), 7);
    }
}
