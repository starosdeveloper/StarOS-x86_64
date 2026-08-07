//! The kernel console: COM1, and the screen when there is one.
//!
//! Two channels for the same reason the aarch64 tree has two — neither is always
//! there. A headless server has COM1 and no display; a laptop has a display and
//! no COM1 at all. Writing to both means the boot log exists on whichever the
//! machine happens to have, and under QEMU it means the same lines are both
//! captured in a file and visible on the emulated panel.
//!
//! ## A global, but not a lock
//! [`Console`] lives in a static from [`init`] onwards, and [`get`] hands out a
//! `&'static mut` to whoever asks. There is no lock, and that is honest for a
//! kernel with one core, no device interrupts and no user space: there is one
//! writer at a time.
//!
//! It has to be reachable from a static because of what phase 1.3 added. A trap
//! handler is not called by anyone — the CPU enters it — so it cannot be handed
//! a console, and a fault that cannot print is a fault that presents as a hang.
//! The two `&mut` that briefly exist (the interrupted code's and the handler's)
//! are never *used* at the same time: a trap suspends the interrupted
//! instruction stream entirely, and when it resumes, the console's cursor has
//! moved. Which is exactly what a mirrored log means.
//!
//! It stops being honest at phase 2.4, when the scheduler makes a second thing
//! able to print, and again at 4.x with secondary cores. The aarch64 tree already
//! learned what that costs: two cores sharing one data register shredded the log
//! character by character, and the fix was a lock held for a whole *message*, not
//! a whole byte. This module will need the same, and the framebuffer needs it
//! more than the UART does — every byte there also moves a shared cursor.

use core::fmt::{self, Write};

use staros_arch_x86_64::serial::Uart16550;
use staros_bootinfo::Framebuffer as FbInfo;
use staros_framebuffer::{Console as FbConsole, Framebuffer, Rgb};
use staros_hal::SerialConsole;

/// Foreground colour of the graphical console.
const FG: Rgb = Rgb::GREEN;
/// Background colour.
const BG: Rgb = Rgb::BLACK;
/// Foreground colour for a fault report. See [`Console::set_alert`].
const ALERT: Rgb = Rgb::RED;

/// The console, once [`init`] has built it.
static mut CONSOLE: Option<Console> = None;

/// Bring up the console and place it in the static.
///
/// Returns the reference `kmain` prints through, so the ordinary boot path does
/// not go through [`get`] and its unwrap.
///
/// # Safety
/// Called once, before anything else drives COM1 or prints.
pub unsafe fn init() -> &'static mut Console {
    // SAFETY: first code to run after the loader; nothing else drives COM1.
    let console = unsafe { Console::new() };
    let slot = &raw mut CONSOLE;
    // SAFETY: `CONSOLE` is private to this module, and the caller guarantees
    // this is the only initialisation.
    unsafe {
        (*slot) = Some(console);
        (*slot).as_mut().expect("just assigned")
    }
}

/// The console, if one has been built.
///
/// `None` before [`init`], which is the window in which a trap has nowhere to
/// report to.
///
/// # Safety
/// The caller must not use the returned reference while another one obtained
/// from here or from [`init`] is also being used. See the module documentation
/// for why a trap handler satisfies that despite appearances.
#[must_use]
pub unsafe fn get() -> Option<&'static mut Console> {
    let slot = &raw mut CONSOLE;
    // SAFETY: forwarded from this function's contract.
    unsafe { (*slot).as_mut() }
}

/// The console every kernel message goes through.
pub struct Console {
    uart: Uart16550,
    have_serial: bool,
    screen: Option<FbConsole<'static>>,
}

impl Console {
    /// Bring up the serial console. The screen is attached later, by
    /// [`Console::attach_screen`], because it needs the hand-off parsed first and
    /// the serial console is what reports a failure to parse it.
    ///
    /// # Safety
    /// Called once, before anything else drives COM1.
    pub unsafe fn new() -> Self {
        let uart = Uart16550::com1();
        // SAFETY: first code to run after the loader; nothing else drives COM1.
        let have_serial = unsafe { uart.init() };
        Self { uart, have_serial, screen: None }
    }

    /// Whether COM1 answered the loopback probe.
    #[must_use]
    pub const fn have_serial(&self) -> bool {
        self.have_serial
    }

    /// Whether messages are being drawn to a screen as well.
    #[must_use]
    pub const fn have_screen(&self) -> bool {
        self.screen.is_some()
    }

    /// Wrap the firmware's framebuffer and start mirroring output to it.
    ///
    /// Returns why it did not, if it did not: a machine with no display is a
    /// normal outcome, but a machine that *reported* a display the kernel then
    /// silently failed to use is a bug that hides itself.
    ///
    /// # Safety
    /// `info` must be a framebuffer the loader mapped, of exactly
    /// `height * stride` bytes, that nothing else writes. Called at most once.
    pub unsafe fn attach_screen(&mut self, info: FbInfo) -> Result<(), &'static str> {
        if !info.is_sane() {
            return Err("firmware reported geometry that is not self-consistent");
        }
        let len = usize::try_from(info.bytes()).map_err(|_| "framebuffer larger than the address space")?;

        // Through the linear map, not the identity map. Both reach it today, but
        // the identity map is the loader's scaffolding and phase 1.4 tears it
        // down; addressing the screen through the map that survives means the
        // console does not have to be rebuilt then.
        let virt = staros_bootinfo::phys_to_virt(info.phys);
        // SAFETY: the caller guarantees the loader mapped exactly this range and
        // that nothing else touches it; the slice lives as long as the kernel.
        let buf: &'static mut [u8] = unsafe { core::slice::from_raw_parts_mut(virt as *mut u8, len) };

        // Prove the mapping before drawing on it: a stride mistake or a short
        // mapping shows up here as a readback mismatch rather than as a screen
        // full of noise, and the last pixel of the last row is exactly the byte a
        // width-based (rather than stride-based) mapping would have left out.
        selftest(buf, &info)?;

        let fb = Framebuffer::new(
            buf,
            info.width as usize,
            info.height as usize,
            info.stride as usize,
            info.format.to_framebuffer(),
        )
        .ok_or("framebuffer geometry does not fit the mapping")?;

        let mut screen = FbConsole::new(fb, FG, BG);
        // ASCII only: this is drawn by the 8x8 font, which has no em-dash.
        let _ = writeln!(
            screen,
            "STAR OS framebuffer console - {}x{} ({} cols x {} rows)",
            info.width,
            info.height,
            screen.cols(),
            screen.rows()
        );
        self.screen = Some(screen);
        Ok(())
    }

    /// Switch the screen between the ordinary colour and the fault colour.
    ///
    /// Only the screen: a serial terminal's colours are the terminal's business,
    /// and a fault report that emits escape sequences into a log file is worse to
    /// read, not better. On a machine with no serial port this is the only thing
    /// separating a fault report from the boot log around it.
    pub fn set_alert(&mut self, alert: bool) {
        if let Some(screen) = self.screen.as_mut() {
            screen.set_fg(if alert { ALERT } else { FG });
        }
    }

    /// Draw the printable ASCII range, so the font can be judged by eye.
    ///
    /// Nothing here can be asserted from a serial log — whether a glyph is the
    /// right shape is a question for a screenshot. What it does prove
    /// mechanically is that a full screen of output wraps and scrolls without
    /// running off the end of the mapping.
    pub fn screen_selftest(&mut self) {
        let Some(screen) = self.screen.as_mut() else {
            return;
        };
        let _ = writeln!(screen, "font self-test: printable ASCII, then a scroll");
        let mut line = [0u8; 32];
        let mut n = 0;
        for byte in 0x20u8..0x7F {
            line[n] = byte;
            n += 1;
            if n == line.len() {
                for &b in &line {
                    screen.write_byte(b);
                }
                screen.write_byte(b'\n');
                n = 0;
            }
        }
        for &b in &line[..n] {
            screen.write_byte(b);
        }
        screen.write_byte(b'\n');
    }
}

/// Write a known value to the corners of the mapping and read it back.
///
/// The interesting corner is the last: `stride` bytes per row means the final
/// pixel lives at `(height - 1) * stride + (width - 1) * 4`, which is past
/// `width * height * 4` on every padded mode. A mapping sized the naive way
/// faults there — and faults, right now, with no IDT, meaning a silent reset. So
/// this touches that byte deliberately, while the only thing that has happened is
/// a boot, rather than discovering it during the first screenful of log.
///
/// It cannot check channel order: red-for-blue reads back exactly as written.
/// That one is for eyes, and [`Console::screen_selftest`] is what to look at.
fn selftest(buf: &mut [u8], info: &FbInfo) -> Result<(), &'static str> {
    let stride = info.stride as usize;
    let corners = [
        (0usize, 0usize),
        (info.width as usize - 1, 0),
        (0, info.height as usize - 1),
        (info.width as usize - 1, info.height as usize - 1),
    ];
    // A pattern with all four bytes different, so a swapped or dropped byte is a
    // mismatch rather than a coincidence.
    const PATTERN: u32 = 0x1234_5678;
    for (i, (x, y)) in corners.iter().enumerate() {
        let off = y * stride + x * 4;
        let word = PATTERN.rotate_left(i as u32 * 8);
        let Some(slot) = buf.get_mut(off..off + 4) else {
            return Err("framebuffer mapping is shorter than its own geometry");
        };
        slot.copy_from_slice(&word.to_le_bytes());
    }
    for (i, (x, y)) in corners.iter().enumerate() {
        let off = y * stride + x * 4;
        let word = PATTERN.rotate_left(i as u32 * 8);
        let got = u32::from_le_bytes(buf[off..off + 4].try_into().expect("4 bytes"));
        if got != word {
            return Err("framebuffer readback mismatch - wrong stride, or not really mapped");
        }
    }
    Ok(())
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.have_serial {
            for byte in s.bytes() {
                // Terminals want CRLF; a kernel log that renders as a staircase is
                // harder to read at exactly the moment reading it matters.
                if byte == b'\n' {
                    self.uart.write_byte(b'\r');
                }
                self.uart.write_byte(byte);
            }
        }
        if let Some(screen) = self.screen.as_mut() {
            // The glyph console handles '\n' itself and has no notion of a
            // carriage return, so the string goes across unmodified.
            screen.write_str(s);
        }
        Ok(())
    }
}
