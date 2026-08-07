//! STAR OS microkernel — the x86_64 PC binary.
//!
//! Entered by the loader (see `docs/SPEC.md` §2) with a pointer to a
//! [`BootInfo`] in `RDI`, after `ExitBootServices`: the firmware is gone, this
//! code owns the machine, and nothing is set up that the loader did not set up.
//!
//! What runs today is the first link of the chain — take the kernel's own stack,
//! validate the hand-off, bring up whatever console exists, and say so. Each
//! following stage is specified in `docs/SPEC.md` and sequenced in
//! `docs/ROADMAP.md`; they are absent here rather than stubbed, so the boot log
//! cannot claim a subsystem that has not been written.

#![no_std]
#![no_main]

use core::arch::naked_asm;
use core::fmt::Write;
use core::panic::PanicInfo;

use staros_arch_x86_64::cpu;
use staros_arch_x86_64::serial::Uart16550;
use staros_bootinfo::{BootInfo, BootInfoError};
use staros_hal::SerialConsole;

/// A `core::fmt` sink over the serial console.
///
/// The aarch64 tree's `Pl011` implements `Write` directly; here the HAL trait and
/// the formatting trait are bridged in the kernel, so the arch crate stays a
/// description of hardware rather than of formatting.
struct SerialWriter(Uart16550);

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            // Terminals want CRLF; a kernel log that renders as a staircase is
            // harder to read at exactly the moment reading it matters.
            if byte == b'\n' {
                self.0.write_byte(b'\r');
            }
            self.0.write_byte(byte);
        }
        Ok(())
    }
}

unsafe extern "C" {
    /// Top of the boot stack, from `crates/arch-x86_64/linker.ld`. The 4 KiB
    /// below `__stack_bottom` are a guard page that no `PT_LOAD` segment covers,
    /// so the loader never maps it and an overflow faults instead of eating
    /// `.bss`.
    static __stack_top: u8;
}

/// Kernel entry point.
///
/// Naked, and the first thing it does is take the kernel's own stack. On entry
/// `RSP` still points into the loader's stack — memory that is about to be
/// reclaimed, and that lives in the identity map the kernel is going to tear
/// down. Nothing may be pushed there, which rules out ordinary Rust code, so
/// this stub is assembly and hands off the moment the stack is ours.
///
/// `RDI` is untouched, so the boot-info pointer the loader placed there arrives
/// at [`kmain`] as its first argument under the System V ABI — the same reasoning
/// as taking the DTB in `x0` on aarch64.
///
/// # Safety
/// Entered exactly once, by the loader, with `RDI` holding a valid [`BootInfo`]
/// pointer and the kernel image mapped as `linker.ld` lays it out. Nothing in
/// Rust may call this: it does not return and it replaces the stack.
#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text.start"]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!(
        // The stack top is 4 KiB aligned; `call` then pushes 8 bytes, which is
        // exactly the alignment System V expects at a function's first
        // instruction.
        "lea rsp, [rip + {stack_top}]",
        // End the frame-pointer chain here, so a future backtrace stops at the
        // entry instead of walking into whatever the loader left behind.
        "xor rbp, rbp",
        "call {kmain}",
        // kmain is `-> !`. Reaching this is a contradiction, and `ud2` turns it
        // into an invalid-opcode fault rather than a silent walk into .rodata.
        "ud2",
        stack_top = sym __stack_top,
        kmain = sym kmain,
    )
}

/// The kernel proper, entered on the kernel's own stack.
///
/// # Safety
/// `boot_info` must point to a valid [`BootInfo`] that outlives this call, in
/// memory the loader has mapped. Called exactly once, by [`_start`].
unsafe extern "C" fn kmain(boot_info: *const BootInfo) -> ! {
    // The serial port is the only device available before anything is parsed, so
    // it comes first — including before the boot info is trusted, because a
    // rejected hand-off is precisely the case that needs to be reported.
    let uart = Uart16550::com1();
    // SAFETY: first code to run after the loader; nothing else drives COM1.
    let have_serial = unsafe { uart.init() };
    let mut console = SerialWriter(uart);

    if have_serial {
        let _ = writeln!(console, "\nSTAR OS microkernel (x86_64) v{}", env!("CARGO_PKG_VERSION"));
    }

    // SAFETY: the caller guarantees a valid, live pointer.
    let Some(info) = (unsafe { boot_info.as_ref() }) else {
        let _ = writeln!(console, "loader passed a null boot info pointer");
        cpu::halt()
    };

    match info.validate() {
        Ok(()) => {}
        Err(e) => {
            // Name the failure. A version mismatch means a stale binary on the
            // ESP — the most likely PC boot failure and the one that otherwise
            // looks identical to a hardware fault.
            let why = match e {
                BootInfoError::BadMagic => "magic does not match: this is not a STAR OS hand-off",
                BootInfoError::BadVersion => {
                    "version mismatch: loader and kernel are from different builds"
                }
                BootInfoError::NoMemoryMap => "no memory map: nothing to allocate from",
            };
            let _ = writeln!(console, "boot info rejected - {why}");
            cpu::halt()
        }
    }

    let _ = writeln!(
        console,
        "boot info accepted: {} memory regions, rsdp {:#x}, kernel {:#x}+{:#x}",
        info.memory_map_len, info.rsdp, info.kernel_phys, info.kernel_len,
    );
    match info.framebuffer() {
        Some(fb) => {
            let _ = writeln!(
                console,
                "framebuffer: {}x{} stride {} at {:#x} ({} KiB)",
                fb.width,
                fb.height,
                fb.stride,
                fb.phys,
                fb.bytes() / 1024,
            );
        }
        None => {
            let _ = writeln!(console, "framebuffer: none reported by firmware");
        }
    }

    // Next: the framebuffer console, then GDT/IDT, then the kernel's own page
    // tables and the frame pool. See docs/ROADMAP.md §1.2 onwards. Until those
    // exist this is where the boot ends, and it ends by saying so rather than by
    // wandering into unwritten code.
    //
    // Interrupts are still masked and there is no IDT: the loader left them that
    // way deliberately, and re-enabling them before an IDT exists would turn the
    // first timer tick into a triple fault.
    let _ = writeln!(
        console,
        "phase 1.1 complete: loaded by firmware, own stack, hand-off verified. Halting."
    );
    cpu::halt()
}

/// Panics stop this core and say why on whatever console exists.
///
/// No unwinding (`panic = "abort"` in the profile), and no attempt to continue: a
/// kernel panic means an invariant the rest of the code depends on is already
/// false.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut console = SerialWriter(Uart16550::com1());
    let _ = writeln!(console, "\nKERNEL PANIC: {info}");
    cpu::halt()
}
