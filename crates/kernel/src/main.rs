//! STAR OS microkernel — the x86_64 PC binary.
//!
//! Entered by the loader (see `docs/SPEC.md` §2) with a pointer to a
//! [`BootInfo`] in `RDI`, after `ExitBootServices`: the firmware is gone, this
//! code owns the machine, and nothing is set up that the loader did not set up.
//!
//! What runs today is phases 1 and 2 of `docs/ROADMAP.md` — take the kernel's
//! own stack, validate the hand-off, bring up whatever console exists, install
//! the CPU tables, take ownership of memory, build the kernel's own page tables,
//! move the 8259s, bring up the APICs, calibrate a timer against the HPET, and
//! run two kernel threads under preemption. Every one of those is followed by a
//! self-test that can fail, because the alternative — a table that is subtly
//! wrong — is completely silent.
//!
//! The order below is not a preference. Each stage is the first thing able to
//! report the next stage's failure: the console before the CPU tables, the CPU
//! tables before anything that can fault, memory before the page tables, the page
//! tables before any device mapping, the interrupt controller before the clock,
//! the clock before the scheduler.
//!
//! Everything after this is specified in `docs/SPEC.md` and sequenced in
//! `docs/ROADMAP.md`; those stages are absent here rather than stubbed, so the
//! boot log cannot claim a subsystem that has not been written.

#![no_std]
#![no_main]

// The scheduler allocates: a task's stack and its slot both come from the heap,
// because both are sized by the machine rather than by a number picked in
// advance. `heap` has provided the global allocator since phase 1.4; phase 2.4 is
// the first code to need the collections that sit on top of it.
extern crate alloc;

mod acpi;
mod console;
mod heap;
mod irq;
mod mem;
mod sched;
mod sync;
mod traps;
mod usermode;
mod vm;

use core::arch::naked_asm;
use core::fmt::{self, Write};
use core::panic::PanicInfo;

use staros_arch_x86_64::cpu;
use staros_arch_x86_64::serial::Uart16550;
use staros_bootinfo::{BootInfo, BootInfoError};
use staros_hal::SerialConsole;


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
    // it comes first — including before the boot info is trusted, because the
    // screen is described *by* that hand-off and a rejected one is precisely the
    // case that needs to be reported.
    // SAFETY: first code to run after the loader; nothing else drives COM1, and
    // this is the only initialisation.
    //
    // The handle is zero-sized and the device is behind a lock (see `console`),
    // so this borrow costs nothing and takes nothing away from the trap handler,
    // which makes its own handle when it needs one.
    let console = &mut (unsafe { console::init() });

    let _ = writeln!(console, "\nSTAR OS microkernel (x86_64) v{}", env!("CARGO_PKG_VERSION"));

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

    // Take a copy, and use nothing but the copy from here on.
    //
    // `boot_info` is a *physical* address. It is dereferenceable right now only
    // because the loader's identity map is still in force, and `vm::init` tears
    // that map down — after which the same pointer reads an address nobody maps.
    // The failure is not subtle when it happens, but it is invisible until
    // something reads the hand-off late: everything up to phase 2.1 happened to
    // read it before the switch, and the first field read afterwards was a page
    // fault at a suspiciously low address.
    //
    // A `BootInfo` is `Copy` and small, so the copy lives in this frame, on the
    // kernel's own stack, which is mapped in both trees. The memory map it points
    // *at* is copied separately by `mem::init`, and for the same reason.
    let info = *info;

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
            // SAFETY: the loader mapped exactly `height * stride` bytes at this
            // physical address (both identity and through the linear map) and
            // nothing else in this kernel touches them. Called once.
            match unsafe { console.attach_screen(fb) } {
                Ok(()) => {
                    let _ = writeln!(
                        console,
                        "console: mirroring to the screen (readback self-test passed)"
                    );
                    console.screen_selftest();
                }
                // Reported, not ignored: a display the firmware described and the
                // kernel then failed to use is a bug that would otherwise present
                // as "the screen stayed blank" with no explanation anywhere.
                Err(why) => {
                    let _ = writeln!(console, "console: screen unusable - {why}");
                }
            }
        }
        None => {
            let _ = writeln!(console, "framebuffer: none reported by firmware");
        }
    }
    if !console.have_serial() && !console.have_screen() {
        // Nothing above was seen by anyone. Nothing below will be either.
        cpu::halt()
    }

    // The CPU tables. Until they are loaded, every fault is a triple fault and
    // therefore a silent reset — so this is the first thing after the console,
    // and the console is first only because the tables need somewhere to report
    // failures to.
    //
    // SAFETY: boot core, called once, interrupts still masked as the loader left
    // them.
    unsafe { traps::init() };
    traps::describe(console);

    // Two faults that come back, proving delivery and return both work.
    traps::selftest_recoverable(console);

    // Take ownership of memory: copy the map out of the loader's buffers, carve
    // the heap, build the frame pool.
    //
    // SAFETY: the hand-off has been validated above and nothing has allocated
    // yet, so the loader's memory-map buffer is still intact. Called once.
    let layout = match unsafe { mem::init(&info, boot_info as u64) } {
        Ok(layout) => layout,
        Err(e) => {
            let _ = writeln!(console, "memory: {}", e.as_str());
            cpu::halt()
        }
    };
    let _ = writeln!(
        console,
        "memory: {} MiB described, {} MiB usable, RAM tops out at {:#x}",
        layout.total / (1024 * 1024),
        layout.usable / (1024 * 1024),
        layout.highest_ram,
    );
    if layout.highest != layout.highest_ram {
        // The gap between the two is a device aperture. Following it would build
        // a terabyte of linear map for a machine with half a gigabyte of RAM,
        // which is exactly what the loader did before it learned to filter.
        let _ = writeln!(
            console,
            "memory: device apertures reach {:#x}; the linear map stops at RAM",
            layout.highest,
        );
    }
    mem::describe(console);
    let _ = writeln!(
        console,
        "memory: heap {} KiB at {:#x}, pool {} MiB over {} run(s) in {} tree(s), {} frames managed",
        layout.heap.1 / 1024,
        layout.heap.0,
        layout.pool_bytes / (1024 * 1024),
        layout.pool_runs,
        layout.pool_trees,
        layout.managed_frames,
    );
    // The pool takes every whole frame of every run it was given. Saying so as an
    // equation rather than a claim, because the version before this one managed a
    // quarter of the machine and reported the number without comment.
    let unmanaged = layout.usable - layout.heap.1 - layout.managed_frames as u64 * 4096;
    if unmanaged != 0 || layout.truncated_runs != 0 {
        let _ = writeln!(
            console,
            "memory: {} KiB of usable RAM is not under management ({} run(s) did not fit)",
            unmanaged / 1024,
            layout.truncated_runs,
        );
    }

    // The kernel's own page tables. After this the loader's tree is gone, and
    // with it the identity map that has been keeping address zero alive.
    //
    // SAFETY: the frame pool exists, this is the boot core, interrupts are
    // masked, and `kernel_phys` comes from the validated hand-off.
    let tables = match unsafe { vm::init(console, info.kernel_phys, layout.highest_ram, info.framebuffer()) } {
        Ok(tables) => tables,
        Err(e) => {
            let _ = writeln!(console, "vm: refusing to switch tables - {e}");
            cpu::halt()
        }
    };
    let _ = writeln!(
        console,
        "vm: cr3 {:#x}, linear {} GiB ({} pages), smep {}, smap {}",
        tables.root,
        tables.linear_bytes / (1024 * 1024 * 1024),
        if tables.gib_pages { "1 GiB" } else { "2 MiB" },
        if tables.smep { "on" } else { "unsupported" },
        if tables.smap { "on" } else { "unsupported" },
    );

    // Three things the log could not say before this point.
    let mut ok = vm::selftest_null(console);
    ok &= vm::selftest_smap(console, &tables);
    ok &= mem::selftest(console);

    // The 8259s, which the firmware left enabled and delivering on the CPU's own
    // exception vectors. Until they are moved, `sti` turns the first stray
    // interrupt into a fault report naming an exception that never happened.
    //
    // SAFETY: boot core, called once, interrupts still masked — reprogramming a
    // live interrupt controller is how one gets delivered mid-sequence.
    unsafe { irq::init(console) };

    // And the first time this kernel has ever run with interrupts enabled. The
    // 8254 supplies one real hardware interrupt so the remap can be checked by
    // something other than assertion: the 8259's vector base is write-only, so
    // where it delivers is a question only a delivered interrupt can answer.
    ok &= irq::selftest(console);

    // And the real controller. Everything the APICs need is in ACPI: where they
    // are, how many cores there are, and — the fact that cannot be guessed —
    // which global system interrupt a legacy IRQ actually arrives on.
    //
    // SAFETY: the linear map is live and `rsdp` comes from the validated hand-off.
    match unsafe { acpi::discover(console, info.rsdp) } {
        Some(facts) => {
            facts.describe(console);
            // SAFETY: boot core, called once, interrupts masked, tables live.
            match unsafe { irq::init_apic(console, &tables, &facts) } {
                // SAFETY: the APICs are up and interrupts are still masked.
                Ok(()) => {
                    // SAFETY: the APICs are up and interrupts are still masked.
                    ok &= unsafe { irq::selftest_apic(console, &facts) };

                    // And a clock. Until now the only measure of time in this
                    // kernel has been a spin count, which had to be guessed and
                    // was guessed wrong once already.
                    //
                    // SAFETY: the APICs are up, interrupts are masked, tables live.
                    match unsafe { irq::init_timer(console, &tables, &facts) } {
                        // SAFETY: the timer is calibrated and stopped.
                        Ok(rate) => {
                            // SAFETY: the timer is calibrated and stopped.
                            ok &= unsafe { irq::selftest_timer(console, rate) };

                            // And something for the ticks to do. Until now every
                            // tick was counted and discarded; from here one of
                            // them can take the CPU away from whoever has it.
                            //
                            // SAFETY: the timer is calibrated, the APICs are up
                            // and the IDT is installed. Runs once.
                            ok &= unsafe { sched::selftest(console) };

                            // And the last thing the kernel owns outright: the
                            // privilege level. Everything so far has run in ring
                            // 0, where a bug is the kernel's own; from here there
                            // is code the kernel does not trust.
                            //
                            // SAFETY: the tables are live, the GDT holds the
                            // selectors `IA32_STAR` names, and interrupts are
                            // masked. Runs once.
                            match unsafe { usermode::init(console, &tables) } {
                                Ok(()) => {
                                    // SAFETY: `init` succeeded and the timer is
                                    // calibrated. Runs once.
                                    ok &= unsafe { usermode::selftest(console) };
                                    // SAFETY: as above, and after `selftest`.
                                    ok &= unsafe { usermode::selftest_noncanonical(console) };
                                }
                                Err(e) => {
                                    let _ = writeln!(console, "user SELF-TEST FAILED: {e}");
                                    ok = false;
                                }
                            }
                        }
                        Err(e) => {
                            let _ = writeln!(console, "timer SELF-TEST FAILED: {e}");
                            ok = false;
                        }
                    }
                }
                Err(e) => {
                    let _ = writeln!(console, "apic SELF-TEST FAILED: {e}");
                    ok = false;
                }
            }
        }
        None => {
            // Not fatal in principle — the 8259s work — but this kernel is not
            // going to grow a legacy-only path, so saying so and stopping is
            // more honest than carrying on with a controller that has no future.
            let _ = writeln!(console, "acpi SELF-TEST FAILED: no usable MADT, cannot reach the APICs");
            ok = false;
        }
    }

    // The completion line is a claim, so it is only made when it is true. A boot
    // that prints "complete" after a failed self-test is worse than one that
    // prints nothing: it is the line a later reader will trust.
    if !ok {
        let _ = writeln!(console, "a self-test failed; not claiming phase 3.1. Halting.");
        cpu::halt()
    }
    let _ = writeln!(
        console,
        "phase 3.1 complete: code the kernel does not trust ran, and came back."
    );

    // And one that does not come back. Last, deliberately: it is the only proof
    // that the IST works, and the proof consumes the machine.
    //
    // SAFETY: nothing after this runs, which is the contract.
    unsafe { traps::selftest_stack_guard(console) }
}

/// Panics stop this core and say why on whatever console exists.
///
/// No unwinding (`panic = "abort"` in the profile), and no attempt to continue: a
/// kernel panic means an invariant the rest of the code depends on is already
/// false.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Serial directly, not through [`Console`]: the panicking code may be holding
    // it — and later, once it is a locked global, may be holding its lock. A
    // panic handler that can deadlock is a panic handler that eats the message
    // explaining the panic.
    let uart = Uart16550::com1();
    let mut w = SerialOnly(uart);
    let _ = writeln!(w, "\nKERNEL PANIC: {info}");
    cpu::halt()
}

/// The panic path's private sink. See [`panic`].
struct SerialOnly(Uart16550);

impl Write for SerialOnly {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.0.write_byte(b'\r');
            }
            self.0.write_byte(byte);
        }
        Ok(())
    }
}
