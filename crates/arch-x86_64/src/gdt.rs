//! The Global Descriptor Table, the Task State Segment, and the selectors.
//!
//! In 64-bit mode segmentation is almost gone: bases and limits are ignored for
//! code and data, and what survives is a handful of bits that still matter —
//! the privilege level, the L bit that says "this is 64-bit code", and the
//! descriptor that points at the TSS.
//!
//! Two things make this table load-bearing rather than ceremonial.
//!
//! ## The TSS is where the IST lives
//! The Interrupt Stack Table is seven pointers inside the TSS, and an IDT entry
//! may name one of them: when that vector is delivered, the CPU switches to that
//! stack *unconditionally*, whatever `RSP` was. That is the only mechanism that
//! lets a fault be handled when the current stack is the problem. Without it, a
//! kernel stack overflow faults on the guard page, the CPU tries to push the
//! fault frame onto the same broken stack, faults again, and the machine resets
//! with nothing printed. It is the same reasoning as the user-stack guard page in
//! the aarch64 tree, one level down: the guard only helps if something survives
//! to report it.
//!
//! ## The layout is fixed by `SYSCALL`/`SYSRET`, not by taste
//! `IA32_STAR` does not hold selectors, it holds two *bases*. `SYSCALL` loads
//! `CS = STAR[47:32]` and `SS = STAR[47:32] + 8`; `SYSRET` in 64-bit mode loads
//! `CS = STAR[63:48] + 16` and `SS = STAR[63:48] + 8`. So kernel code must be
//! immediately followed by kernel data, and the user entries must run
//! 32-bit code, data, 64-bit code — in that order, with no gaps. [`USER_CODE32`]
//! is never selected by this kernel and exists only to hold that slot. Getting
//! this wrong is not a compile error and not a boot failure; it is a wrong `SS`
//! on the first return to user space in phase 2.

#[cfg(not(test))]
use core::arch::asm;
use core::mem::size_of;

/// Selector for the kernel's 64-bit code segment. RPL 0.
pub const KERNEL_CODE: u16 = 0x08;
/// Selector for the kernel's data segment (also `SS`). RPL 0.
pub const KERNEL_DATA: u16 = 0x10;
/// Placeholder holding the slot `SYSRET` requires. Never loaded. See the module
/// documentation.
pub const USER_CODE32: u16 = 0x18 | 3;
/// Selector for the user data segment. RPL 3.
pub const USER_DATA: u16 = 0x20 | 3;
/// Selector for the user 64-bit code segment. RPL 3.
pub const USER_CODE: u16 = 0x28 | 3;
/// Selector for the TSS descriptor, which occupies two GDT slots.
pub const TSS_SELECTOR: u16 = 0x30;

/// IST slot used by the double-fault vector. See the module documentation.
pub const IST_DOUBLE_FAULT: u8 = 1;
/// IST slot used by the non-maskable interrupt.
///
/// An NMI can land anywhere, including inside the first few instructions of
/// another handler and including on a stack that is already broken. It gets its
/// own stack for the same reason `#DF` does.
pub const IST_NMI: u8 = 2;
/// IST slot used by the machine-check vector.
pub const IST_MACHINE_CHECK: u8 = 3;

/// Size of each IST stack.
///
/// 16 KiB: enough for a fault report that formats numbers and draws glyphs, and
/// small enough that three of them are 48 KiB of `.bss`. These have **no guard
/// page** — the kernel does not own its page tables until phase 1.4, so nothing
/// here can unmap anything. Overflowing one is silent, which is why nothing but
/// a fault report is allowed to run on them.
#[cfg(not(test))]
const IST_STACK_SIZE: usize = 16 * 1024;

/// Number of GDT slots: null, kernel code/data, three user entries, and the
/// two-slot TSS descriptor.
#[cfg(not(test))]
const GDT_SLOTS: usize = 8;

/// One IST stack, aligned so the CPU's pushes are aligned from the first one.
#[cfg(not(test))]
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

#[cfg(not(test))]
static mut DOUBLE_FAULT_STACK: IstStack = IstStack([0; IST_STACK_SIZE]);
#[cfg(not(test))]
static mut NMI_STACK: IstStack = IstStack([0; IST_STACK_SIZE]);
#[cfg(not(test))]
static mut MACHINE_CHECK_STACK: IstStack = IstStack([0; IST_STACK_SIZE]);

#[cfg(not(test))]
static mut GDT: [u64; GDT_SLOTS] = [0; GDT_SLOTS];
#[cfg(not(test))]
static mut TSS: Tss = Tss::new();

/// The Task State Segment, as 64-bit mode redefines it.
///
/// Nothing here is a task: hardware task switching does not exist in long mode.
/// What is left is two arrays of stack pointers — `privilege_stacks` for
/// ring transitions and `interrupt_stacks` for the IST — plus the I/O permission
/// bitmap offset.
///
/// `packed`, and that is not a style choice: the architecture defines `rsp0` at
/// offset 4, so every 64-bit field in this structure is misaligned by design.
#[repr(C, packed)]
pub struct Tss {
    reserved0: u32,
    /// `RSP` loaded on a transition into rings 0, 1 and 2.
    pub privilege_stacks: [u64; 3],
    reserved1: u64,
    /// The Interrupt Stack Table. IDT entry `ist = n` selects index `n - 1`.
    pub interrupt_stacks: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// Offset of the I/O permission bitmap. Set to the TSS size, meaning "the
    /// bitmap starts past the end of the segment", which the CPU reads as
    /// "no port is permitted in ring 3".
    pub iomap_base: u16,
}

impl Tss {
    /// An empty TSS. All stacks null until [`install`] fills them.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            privilege_stacks: [0; 3],
            reserved1: 0,
            interrupt_stacks: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iomap_base: 0,
        }
    }
}

impl Default for Tss {
    fn default() -> Self {
        Self::new()
    }
}

/// The operand of `lgdt` and `lidt`: a limit and a base, in that order.
///
/// `packed` because the architecture puts a 64-bit base immediately after a
/// 16-bit limit, with no padding.
#[repr(C, packed)]
pub struct DescriptorTablePointer {
    /// Size of the table in bytes, minus one.
    pub limit: u16,
    /// Linear address of the table.
    pub base: u64,
}

/// Build a flat code or data descriptor.
///
/// `access` is the type byte (present, DPL, S, and the type nibble); `flags` is
/// the granularity nibble (`G`, `D/B`, `L`, `AVL`). The base is zero and the
/// limit is the full 4 GiB, because in 64-bit mode both are ignored — carrying
/// the conventional values costs nothing and keeps the descriptors recognisable
/// against any reference table.
#[must_use]
pub const fn segment(access: u8, flags: u8) -> u64 {
    const LIMIT: u64 = 0xF_FFFF;
    (LIMIT & 0xFFFF)
        | ((access as u64) << 40)
        | (((LIMIT >> 16) & 0xF) << 48)
        | (((flags as u64) & 0xF) << 52)
}

/// Kernel 64-bit code: present, DPL 0, code, readable, `L` set, `G` set.
pub const KERNEL_CODE_DESC: u64 = segment(0x9A, 0xA);
/// Kernel data: present, DPL 0, data, writable, `D/B` set, `G` set.
pub const KERNEL_DATA_DESC: u64 = segment(0x92, 0xC);
/// User 32-bit code. Holds the `SYSRET` slot; never loaded.
pub const USER_CODE32_DESC: u64 = segment(0xFA, 0xC);
/// User data: present, DPL 3, data, writable.
pub const USER_DATA_DESC: u64 = segment(0xF2, 0xC);
/// User 64-bit code: present, DPL 3, code, readable, `L` set.
pub const USER_CODE_DESC: u64 = segment(0xFA, 0xA);

/// Build the two halves of a 64-bit TSS descriptor.
///
/// Unlike a code or data descriptor this one is sixteen bytes and its base is
/// real: it is how the CPU finds the IST. Type `0x9` is "64-bit TSS, available";
/// `0xB` would be "busy", which `ltr` refuses.
#[must_use]
pub const fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let limit = limit as u64;
    let low = (limit & 0xFFFF)
        | ((base & 0x00FF_FFFF) << 16)
        | (0x89 << 40)
        | (((limit >> 16) & 0xF) << 48)
        | (((base >> 24) & 0xFF) << 56);
    (low, base >> 32)
}

/// Address one past the end of an IST stack: where the CPU starts pushing.
#[cfg(not(test))]
fn stack_top(stack: *mut IstStack) -> u64 {
    (stack as u64) + IST_STACK_SIZE as u64
}

/// Install the GDT and TSS and load every segment register from them.
///
/// After this returns, the descriptors the firmware left behind are no longer
/// referenced by anything — which matters, because they live in memory that
/// `ExitBootServices` released.
///
/// # Safety
/// Called once per core, with interrupts masked. Replacing the descriptor tables
/// while an interrupt could be delivered means delivering it through a table
/// that is half old and half new.
#[cfg(not(test))]
pub unsafe fn install() {
    let tss = &raw mut TSS;
    // SAFETY: `TSS` is a private static and this is the only writer; the pointer
    // is derived from it directly, so it is valid and aligned for its own type.
    unsafe {
        (*tss).interrupt_stacks[IST_DOUBLE_FAULT as usize - 1] = stack_top(&raw mut DOUBLE_FAULT_STACK);
        (*tss).interrupt_stacks[IST_NMI as usize - 1] = stack_top(&raw mut NMI_STACK);
        (*tss).interrupt_stacks[IST_MACHINE_CHECK as usize - 1] = stack_top(&raw mut MACHINE_CHECK_STACK);
        // No ring-3 code exists yet, so no transition can consume `rsp0`. It is
        // left null deliberately: phase 2 must set it to the current thread's
        // kernel stack, and a null there faults loudly rather than landing on
        // whatever stack happened to be reused.
        (*tss).iomap_base = size_of::<Tss>() as u16;
    }

    let (tss_low, tss_high) = tss_descriptor(tss as u64, (size_of::<Tss>() - 1) as u32);
    let gdt = &raw mut GDT;
    // SAFETY: same reasoning; `GDT` is private to this module and single-writer.
    unsafe {
        (*gdt) = [
            0,
            KERNEL_CODE_DESC,
            KERNEL_DATA_DESC,
            USER_CODE32_DESC,
            USER_DATA_DESC,
            USER_CODE_DESC,
            tss_low,
            tss_high,
        ];
    }

    let pointer = DescriptorTablePointer {
        limit: (size_of::<[u64; GDT_SLOTS]>() - 1) as u16,
        base: gdt as u64,
    };
    // SAFETY: `pointer` describes the table just built, which is a live static;
    // `lgdt` only reads through it.
    unsafe {
        asm!("lgdt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }

    // SAFETY: the GDT is loaded and holds the selectors used below.
    unsafe { reload_segments() };

    // SAFETY: slot 6 now holds an available 64-bit TSS descriptor whose base is
    // the live `TSS` static.
    unsafe {
        asm!("ltr {0:x}", in(reg) TSS_SELECTOR, options(nostack, preserves_flags));
    }
}

/// Point every segment register at the new table.
///
/// `CS` cannot be assigned; the only ways to change it are a far jump, a far
/// call, a far return or an interrupt return. A far return is the cheapest:
/// push the new selector and the address to continue at, then `retfq` pops both.
///
/// # Safety
/// A GDT containing [`KERNEL_CODE`] and [`KERNEL_DATA`] must already be loaded.
#[cfg(not(test))]
unsafe fn reload_segments() {
    // SAFETY: forwarded from this function's contract. The block pushes, so it
    // is not `nostack`; it changes no flags.
    unsafe {
        asm!(
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov ss, {data:x}",
            "mov fs, {data:x}",
            "mov gs, {data:x}",
            code = in(reg) u64::from(KERNEL_CODE),
            data = in(reg) u32::from(KERNEL_DATA),
            tmp = out(reg) _,
            options(preserves_flags),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The descriptors are compared against literals rather than recomputed:
    // a test that repeats the formula would agree with any mistake in it. These
    // values are the ones every reference table prints for a flat 64-bit kernel.
    #[test]
    fn kernel_descriptors_match_the_architecture_reference() {
        assert_eq!(KERNEL_CODE_DESC, 0x00AF_9A00_0000_FFFF);
        assert_eq!(KERNEL_DATA_DESC, 0x00CF_9200_0000_FFFF);
    }

    #[test]
    fn user_descriptors_carry_dpl_3() {
        assert_eq!(USER_CODE32_DESC, 0x00CF_FA00_0000_FFFF);
        assert_eq!(USER_DATA_DESC, 0x00CF_F200_0000_FFFF);
        assert_eq!(USER_CODE_DESC, 0x00AF_FA00_0000_FFFF);
        // Bits 45:46 are the DPL. All three must be ring 3, or user code runs
        // with kernel privilege and nothing reports it.
        for desc in [USER_CODE32_DESC, USER_DATA_DESC, USER_CODE_DESC] {
            assert_eq!((desc >> 45) & 0b11, 3, "{desc:#x} is not DPL 3");
        }
    }

    #[test]
    fn code_and_data_differ_only_where_they_should() {
        // The L bit (64-bit code) belongs to code and the D/B bit to data;
        // setting both is the classic descriptor bug, and the CPU rejects it
        // rather than ignoring it.
        assert_eq!((KERNEL_CODE_DESC >> 53) & 1, 1, "kernel code is not 64-bit");
        assert_eq!((KERNEL_CODE_DESC >> 54) & 1, 0, "kernel code has D/B set with L");
        assert_eq!((KERNEL_DATA_DESC >> 53) & 1, 0, "kernel data has L set");
    }

    #[test]
    fn selectors_index_the_slots_the_descriptors_occupy() {
        // Selector = index * 8 | RPL, and the SYSCALL/SYSRET layout constrains
        // the order. If these ever drift, phase 2 returns to user space with the
        // wrong SS and the failure looks like a scheduler bug.
        assert_eq!(KERNEL_CODE >> 3, 1);
        assert_eq!(KERNEL_DATA >> 3, 2);
        assert_eq!(KERNEL_DATA, KERNEL_CODE + 8, "SYSCALL requires SS = CS + 8");
        assert_eq!(USER_CODE32 & !3, 0x18);
        assert_eq!(USER_DATA & !3, (USER_CODE32 & !3) + 8, "SYSRET requires SS = base + 8");
        assert_eq!(USER_CODE & !3, (USER_CODE32 & !3) + 16, "SYSRET requires CS = base + 16");
        assert_eq!(USER_DATA & 3, 3);
        assert_eq!(USER_CODE & 3, 3);
        assert_eq!(TSS_SELECTOR >> 3, 6);
    }

    #[test]
    fn the_tss_is_the_size_the_architecture_says() {
        // 104 bytes. A `repr(C)` that padded the misaligned u64 fields would be
        // larger, the descriptor limit would be wrong, and the CPU would read
        // the IST pointers from the wrong offsets.
        assert_eq!(size_of::<Tss>(), 104);
    }

    #[test]
    fn tss_descriptor_scatters_the_base_the_way_the_cpu_reassembles_it() {
        // A base with a distinct byte in every position, so a misplaced field is
        // a wrong value rather than a coincidence.
        let (low, high) = tss_descriptor(0x1122_3344_5566_7788, 103);
        assert_eq!(low & 0xFFFF, 103, "limit 15:0");
        assert_eq!((low >> 16) & 0xFF_FFFF, 0x0066_7788, "base 23:0");
        assert_eq!((low >> 40) & 0xFF, 0x89, "type: available 64-bit TSS, present");
        assert_eq!((low >> 48) & 0xF, 0, "limit 19:16");
        assert_eq!((low >> 56) & 0xFF, 0x55, "base 31:24");
        assert_eq!(high, 0x1122_3344, "base 63:32");
    }

    #[test]
    fn tss_descriptor_is_available_not_busy() {
        // Type 0xB is "busy", which `ltr` refuses with a #GP. The difference is
        // one bit and the failure is a triple fault during install.
        let (low, _) = tss_descriptor(0, 103);
        assert_eq!((low >> 40) & 0xF, 0x9);
    }

    #[test]
    fn ist_slots_are_distinct_and_one_based() {
        // IDT entry `ist = n` selects `interrupt_stacks[n - 1]`; `ist = 0` means
        // "no switch". Sharing a slot between two vectors means the second
        // fault lands on the first one's frame.
        let slots = [IST_DOUBLE_FAULT, IST_NMI, IST_MACHINE_CHECK];
        for slot in slots {
            assert!((1..=7).contains(&slot), "IST slot {slot} is not in 1..=7");
        }
        assert_eq!(slots.len(), {
            let mut seen = slots;
            seen.sort_unstable();
            seen.windows(2).filter(|w| w[0] != w[1]).count() + 1
        });
    }
}
