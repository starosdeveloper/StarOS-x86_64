//! The kernel console: COM1, and the screen when there is one.
//!
//! Two channels for the same reason the aarch64 tree has two — neither is always
//! there. A headless server has COM1 and no display; a laptop has a display and
//! no COM1 at all. Writing to both means the boot log exists on whichever the
//! machine happens to have, and under QEMU it means the same lines are both
//! captured in a file and visible on the emulated panel.
//!
//! ## The lock, and what it is a lock *on*
//! Until phase 2.4 there was one writer, and this module said so: a `&'static mut`
//! handed to whoever asked, no lock, honest for a kernel with one core, no device
//! interrupts and no tasks. The scheduler ends that. Two tasks print, the timer
//! preempts one of them mid-message, and the log comes out shredded — the exact
//! failure the aarch64 tree hit on four cores and fixed the same way.
//!
//! The unit of exclusion is a **message**, not a byte. A byte-level lock stops
//! two writers corrupting the UART's data register and does nothing whatever
//! about readability: the bytes still interleave, and on the framebuffer — where
//! every byte also moves a shared cursor — the result is worse than on the wire.
//! So [`Console`] is a zero-sized handle, the device lives behind [`LOCK`], and
//! `Write::write_fmt` is overridden to take that lock **once for the whole
//! formatted message** rather than letting the default implementation take it per
//! fragment. `writeln!(console, "x {y}")` lowers to a single `write_fmt` whose
//! format string already carries the newline, so a line is atomic including its
//! terminator.
//!
//! Because [`SpinLock`] masks interrupts on the holding core, a single core is
//! also protected from *itself*: the timer cannot preempt a task in the middle of
//! its own message. That is what makes this correct today, and the ticket lock
//! underneath is what will make it correct at phase 4.
//!
//! ## The one writer that does not take the lock
//! A fatal fault report does not. It cannot: the code it interrupted may be
//! holding the lock, and a ticket lock taken twice on one core is a hang — so the
//! kernel would swallow the message explaining why it died, which is the one
//! message worth never losing. [`emergency`] therefore writes to the device
//! directly, on the grounds that a fault report is the last thing this core will
//! ever print and there is nothing left for it to interleave with. The panic
//! handler already reasoned this way, and goes further still by bypassing this
//! module entirely.

use core::fmt::{self, Arguments, Write};

use staros_arch_x86_64::serial::Uart16550;
use staros_bootinfo::Framebuffer as FbInfo;
use staros_framebuffer::{Console as FbConsole, Framebuffer, Rgb};
use staros_hal::SerialConsole;

use crate::sync::SpinLock;

/// Foreground colour of the graphical console.
const FG: Rgb = Rgb::GREEN;
/// Background colour.
const BG: Rgb = Rgb::BLACK;
/// Foreground colour for a fault report. See [`Emergency::set_alert`].
const ALERT: Rgb = Rgb::RED;

/// Serialises access to the device. Held for a whole message.
///
/// A `SpinLock<()>` rather than a `SpinLock<Device>`, because the emergency path
/// has to reach the device *without* the lock — see the module documentation.
/// What the lock protects is therefore stated here rather than expressed in the
/// type: every access to [`DEVICE`] happens while this is held, except
/// [`emergency`] and the single-threaded [`init`].
static LOCK: SpinLock<()> = SpinLock::new(());

/// The device, once [`init`] has built it.
static mut DEVICE: Option<Device> = None;

/// Bring up the console and place it in the static.
///
/// Returns a handle, so the ordinary boot path does not go through [`get`] and
/// its option.
///
/// # Safety
/// Called once, before anything else drives COM1 or prints.
pub unsafe fn init() -> Console {
    // SAFETY: first code to run after the loader; nothing else drives COM1.
    let device = unsafe { Device::new() };
    let slot = &raw mut DEVICE;
    // SAFETY: `DEVICE` is private to this module and the caller guarantees this
    // is the only initialisation, so nothing else can be looking at it yet.
    unsafe { (*slot) = Some(device) };
    Console(())
}

/// A handle to the console, if one has been built.
///
/// `None` before [`init`], which is the window in which a trap has nowhere to
/// report to.
#[must_use]
pub fn get() -> Option<Console> {
    let slot = &raw const DEVICE;
    // SAFETY: a shared read of an `Option`'s discriminant. The only writer is
    // `init`, which runs before anything can call this.
    if unsafe { (*slot).is_some() } {
        Some(Console(()))
    } else {
        None
    }
}

/// Run `f` against the device with [`LOCK`] held for its whole duration.
///
/// Returns `Err` when there is no device, which formats as an ordinary
/// [`fmt::Error`] — printing before [`init`] is a bug, not a fault, and it must
/// not be able to panic inside a trap handler.
fn with_device(f: impl FnOnce(&mut Device) -> fmt::Result) -> fmt::Result {
    let _guard = LOCK.lock();
    let slot = &raw mut DEVICE;
    // SAFETY: the guard is held, so no other core is here and this core cannot be
    // preempted into here (the lock masks interrupts). The one path that reaches
    // `DEVICE` without the guard is `emergency`, which runs only from a trap that
    // has already suspended whoever held it.
    match unsafe { (*slot).as_mut() } {
        Some(device) => f(device),
        None => Err(fmt::Error),
    }
}

/// The console every kernel message goes through.
///
/// Zero-sized: it names the console, it does not own it. Copying a handle is
/// free and harmless, which is what lets a trap handler get one without taking
/// anything away from the code it interrupted.
#[derive(Clone, Copy)]
pub struct Console(());

impl Console {
    /// Whether COM1 answered the loopback probe.
    #[must_use]
    pub fn have_serial(self) -> bool {
        let mut answer = false;
        let _ = with_device(|device| {
            answer = device.have_serial;
            Ok(())
        });
        answer
    }

    /// Whether messages are being drawn to a screen as well.
    #[must_use]
    pub fn have_screen(self) -> bool {
        let mut answer = false;
        let _ = with_device(|device| {
            answer = device.screen.is_some();
            Ok(())
        });
        answer
    }

    /// Wrap the firmware's framebuffer and start mirroring output to it.
    ///
    /// Returns why it did not, if it did not: a machine with no display is a
    /// normal outcome, but a machine that *reported* a display the kernel then
    /// silently failed to use is a bug that hides itself.
    ///
    /// # Errors
    /// When the geometry is not self-consistent, the mapping is shorter than the
    /// geometry claims, or a readback through it does not return what was
    /// written.
    ///
    /// # Safety
    /// `info` must be a framebuffer the loader mapped, of exactly
    /// `height * stride` bytes, that nothing else writes. Called at most once.
    pub unsafe fn attach_screen(self, info: FbInfo) -> Result<(), &'static str> {
        // SAFETY: forwarded from this function's contract.
        let screen = unsafe { build_screen(info) }?;
        let mut placed = Err("the console is not initialised");
        let _ = with_device(|device| {
            device.screen = Some(screen);
            placed = Ok(());
            Ok(())
        });
        placed
    }

    /// Draw the printable ASCII range, so the font can be judged by eye.
    ///
    /// Nothing here can be asserted from a serial log — whether a glyph is the
    /// right shape is a question for a screenshot. What it does prove
    /// mechanically is that a full screen of output wraps and scrolls without
    /// running off the end of the mapping.
    pub fn screen_selftest(self) {
        let _ = with_device(|device| {
            let Some(screen) = device.screen.as_mut() else {
                return Ok(());
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
            Ok(())
        });
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        with_device(|device| device.write_str(s))
    }

    /// The reason this trait is implemented by hand rather than left to
    /// `write_str` alone.
    ///
    /// The default `write_fmt` calls `write_str` once per literal and once per
    /// interpolated value, so `writeln!(console, "a {b} c")` would take and
    /// release the lock four times and another writer could land between any two
    /// of them. Taking it here instead makes the whole formatted message — the
    /// trailing newline `writeln!` folded into the format string included — a
    /// single hold.
    fn write_fmt(&mut self, args: Arguments<'_>) -> fmt::Result {
        with_device(|device| device.write_fmt(args))
    }
}

/// Write `args` and a newline as one uninterruptible message.
///
/// What [`kprintln!`](crate::kprintln) lowers to. It exists alongside the
/// `writeln!(console, ...)` form because code that has no console handle to hand
/// — a task body, which is entered by a trampoline and passed nothing — still has
/// to be able to print, and the alternative is threading a handle through
/// everything for the sake of a zero-sized value.
pub fn println(args: Arguments<'_>) {
    let _ = with_device(|device| {
        device.write_fmt(args)?;
        device.write_str("\n")
    });
}

/// Print a line through the console, holding the lock for the whole message.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {
        $crate::console::println(::core::format_args!($($arg)*))
    };
}

/// A console handle that does **not** take the lock. See the module docs.
///
/// # Safety
/// Only for a report that ends this core: the caller must be certain no message
/// it interleaves with will ever be read again. It is sound in the sense that
/// matters — a trap has suspended whatever else was writing, so there is no
/// concurrent access — but it is not *orderly*, and using it anywhere else would
/// put fragments of one message inside another.
#[must_use]
pub unsafe fn emergency() -> Emergency {
    Emergency(())
}

/// The fault report's console. See [`emergency`].
#[derive(Clone, Copy)]
pub struct Emergency(());

impl Emergency {
    /// Switch the screen between the ordinary colour and the fault colour.
    ///
    /// Only the screen: a serial terminal's colours are the terminal's business,
    /// and a fault report that emits escape sequences into a log file is worse to
    /// read, not better. On a machine with no serial port this is the only thing
    /// separating a fault report from the boot log around it.
    pub fn set_alert(self, alert: bool) {
        let slot = &raw mut DEVICE;
        // SAFETY: as `Write for Emergency` below.
        if let Some(screen) = unsafe { (*slot).as_mut() }.and_then(|d| d.screen.as_mut()) {
            screen.set_fg(if alert { ALERT } else { FG });
        }
    }
}

impl Write for Emergency {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let slot = &raw mut DEVICE;
        // SAFETY: the caller of `emergency` has promised this runs from a trap
        // that suspended every other writer on this core, and this kernel has one
        // core. Deliberately not taking `LOCK`: the suspended writer may be
        // holding it, and waiting for a lock its holder can never release would
        // eat the fault report.
        match unsafe { (*slot).as_mut() } {
            Some(device) => device.write_str(s),
            None => Err(fmt::Error),
        }
    }
}

/// The console's two output channels.
struct Device {
    uart: Uart16550,
    have_serial: bool,
    screen: Option<FbConsole<'static>>,
}

impl Device {
    /// Bring up the serial console. The screen is attached later, by
    /// [`Console::attach_screen`], because it needs the hand-off parsed first and
    /// the serial console is what reports a failure to parse it.
    ///
    /// # Safety
    /// Called once, before anything else drives COM1.
    unsafe fn new() -> Self {
        let uart = Uart16550::com1();
        // SAFETY: first code to run after the loader; nothing else drives COM1.
        let have_serial = unsafe { uart.init() };
        Self { uart, have_serial, screen: None }
    }
}

impl Write for Device {
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

/// Validate the firmware's framebuffer and wrap it in a glyph console.
///
/// # Safety
/// As [`Console::attach_screen`], whose contract this carries out.
unsafe fn build_screen(info: FbInfo) -> Result<FbConsole<'static>, &'static str> {
    if !info.is_sane() {
        return Err("firmware reported geometry that is not self-consistent");
    }
    let len =
        usize::try_from(info.bytes()).map_err(|_| "framebuffer larger than the address space")?;

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
    Ok(screen)
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
