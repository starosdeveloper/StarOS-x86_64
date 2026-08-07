//! STAR OS UEFI loader — entry point.
//!
//! Deliberately thin. Everything the loader does lives in the library half of
//! this crate (`boot::run`), which also compiles for the host so its
//! interpretation of firmware data can be tested. What is left here is what
//! genuinely cannot be: the firmware's calling convention, and what to do when
//! the sequence fails.
//!
//! On failure the loader prints the named stage and stops, rather than returning
//! an error status to the firmware. Returning would send the machine to the next
//! boot option — a different OS, or a boot menu — and the message explaining why
//! would scroll away in the process.

#![no_std]
#![no_main]

use core::fmt::Write;
use core::panic::PanicInfo;

use staros_arch_x86_64::cpu;
use staros_boot_uefi::boot;
use staros_boot_uefi::console::Console;
use staros_boot_uefi::efi::{Handle, Status, SystemTable};
use staros_hal::SerialConsole;

/// Firmware entry point.
///
/// The `x86_64-unknown-uefi` target expects this exact symbol; `efiapi` is the
/// Microsoft x64 convention the firmware calls with, which is one of the reasons
/// the kernel proper is a separate binary (see `docs/SPEC.md` §2.1).
///
/// # Safety
/// Called once, by firmware, with a valid image handle and a live system table.
/// Nothing in this program calls it.
#[no_mangle]
pub unsafe extern "efiapi" fn efi_main(
    image: Handle,
    system_table: *mut SystemTable,
) -> Status {
    // SAFETY: the firmware guarantees a valid system table for the life of this
    // image; this is the first code to run in it.
    let st = unsafe { &*system_table };
    // SAFETY: `con_out` is the firmware's live console.
    let mut console = unsafe { Console::new(st.con_out) };

    let _ = writeln!(console, "\nSTAR OS loader v{} (x86_64 UEFI)", env!("CARGO_PKG_VERSION"));
    if !console.have_serial() {
        // Worth saying once: on a machine with no COM1 the kernel's own log will
        // be invisible until the framebuffer console exists, and knowing that in
        // advance is the difference between "broken" and "expected".
        let _ = writeln!(console, "note: no COM1 - firmware console only until the kernel is up");
    }

    // SAFETY: `image` and `st` are exactly what the firmware passed.
    match unsafe { boot::run(image, st, &mut console) } {
        // `run` returns `Infallible` on success because it does not return at
        // all: control has left for the kernel by then.
        Ok(never) => match never {},
        Err(e) => {
            let _ = writeln!(console, "\nBOOT FAILED: {e}");
            let _ = writeln!(console, "halting - the kernel was not entered");
            cpu::halt()
        }
    }
}

/// A panic in the loader is a bug in the loader; say so and stop.
///
/// Not `Status`-returning for the same reason a failed boot is not: continuing
/// would hand the machine to another boot option and lose the message.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Serial only. A panic can happen after `ExitBootServices`, when the firmware
    // console pointer is no longer callable, and this handler cannot know which
    // side of that line it is on.
    let uart = staros_arch_x86_64::serial::Uart16550::com1();
    // SAFETY: nothing else is driving COM1 at this point, by construction.
    unsafe { uart.init() };
    for b in b"\r\nLOADER PANIC: " {
        uart.write_byte(*b);
    }
    let mut w = SerialOnly(uart);
    let _ = writeln!(w, "{info}");
    cpu::halt()
}

/// Minimal serial sink for the panic path, which cannot use [`Console`] because
/// that one may still hold a firmware pointer.
struct SerialOnly(staros_arch_x86_64::serial::Uart16550);

impl Write for SerialOnly {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.0.write_byte(b'\r');
            }
            self.0.write_byte(b);
        }
        Ok(())
    }
}
