//! STAR OS microkernel — the x86_64 PC binary.
//!
//! Entered by the loader (see `docs/SPEC.md` §2) with a pointer to a
//! [`BootInfo`] in `RDI`, after `ExitBootServices`: the firmware is gone, this
//! code owns the machine, and nothing is set up that the loader did not set up.
//!
//! What runs today is the first link of the chain — validate the hand-off, bring
//! up whatever console exists, and say so. Each following stage is specified in
//! `docs/SPEC.md` and sequenced in `docs/ROADMAP.md`; they are absent here rather
//! than stubbed, so the boot log cannot claim a subsystem that has not been
//! written.

#![no_std]
#![no_main]

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

/// Kernel entry point.
///
/// `extern "C"` and one argument: the loader jumps here with the boot info
/// pointer in `RDI`, which is the System V ABI's first integer argument. That
/// makes the hand-off an ordinary function call rather than a private convention
/// — the same reasoning as taking the DTB in `x0` on aarch64.
///
/// # Safety
/// `boot_info` must point to a valid [`BootInfo`] that outlives this call, in
/// memory the loader has mapped. Called exactly once, by the loader.
#[no_mangle]
#[link_section = ".text.start"]
pub unsafe extern "C" fn _start(boot_info: *const BootInfo) -> ! {
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

    // Next: the memory map into a frame allocator, then paging, GDT/IDT, APIC.
    // See docs/ROADMAP.md phase 1. Until those exist this is where the boot ends,
    // and it ends by saying so rather than by wandering into unwritten code.
    let _ = writeln!(console, "phase 0 complete: hand-off verified, console up. Halting.");
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
