//! Waking the other cores.
//!
//! Everything up to here ran on the core the firmware happened to start. The rest
//! of the machine has been sitting in a halt state since power-on, and getting it
//! out is a sequence rather than a call: reset the core with an INIT message, tell
//! it where to begin with a startup message, and let the sixteen-bit code in
//! [`staros_arch_x86_64::trampoline`] carry it from real mode to the kernel's own
//! tables.
//!
//! ## Why the delays are part of the contract
//!
//! The architecture manual specifies waits between the messages — 10 ms after
//! INIT, 200 µs between startup attempts — and they are not padding. A core that
//! has just taken INIT is resetting; a startup message that arrives during that
//! is not queued, it is missed. The symptom of skipping them is a core that comes
//! up on some machines and not others, which is the worst possible way to find
//! out.
//!
//! ## Why two startup messages
//!
//! The same manual says to send the second unconditionally and only then wait to
//! see whether the core answered. A core that took the first ignores the second,
//! so the cost of sending it is nothing, and the cost of *not* sending it is a
//! machine where bring-up works everywhere except the one model that needed it.

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use staros_arch_x86_64::apic::LocalApic;
use staros_arch_x86_64::mmio::MappedRegisters;
use staros_arch_x86_64::trampoline;
use staros_bootinfo::phys_to_virt;
/// A page, as a `u64`. `staros_mm::PAGE_SIZE` is a `usize`, and every use here is
/// an address or a length in the 64-bit space the trampoline works in.
const PAGE_BYTES: u64 = staros_mm::PAGE_SIZE as u64;

use crate::acpi::Facts;
use crate::console::Console;
use crate::vm::Tables;

/// Physical page the trampoline is copied to.
///
/// It has to be below 1 MiB, because the startup message carries a page number in
/// eight bits and the core answering it starts in real mode. `0x8000` is clear of
/// the interrupt vector table and the BIOS data area at the bottom, and clear of
/// the legacy video and firmware regions higher up. The frame allocator is not
/// asked for it: this address is a property of the architecture, not a resource
/// to be handed out, and a pool that had already given it to somebody would be
/// the wrong place to find that out.
pub const TRAMPOLINE_PHYS: u64 = 0x8000;

/// Stack size for a core that has just woken. One page while it has nothing to do
/// but announce itself; the scheduler gives it a real stack when it gets a task.
const AP_STACK_PAGES: u64 = 4;

/// How long one interrupt command may take to be accepted.
///
/// Ten milliseconds — three orders of magnitude more than an APIC needs, and a
/// bound that is *time* rather than a spin count. The first version counted a
/// million iterations, each of which is an MMIO read of an emulated APIC: on
/// hardware that is milliseconds, under TCG it is minutes, and the same constant
/// therefore means two completely different waits.
const IPI_TIMEOUT_MICROS: u64 = 10_000;

/// How many cores have reached Rust code with the kernel's tables loaded.
///
/// Starts at one: the boot processor is a core that came up, and counting it
/// separately would make "how many are running" a sum of two numbers that can
/// disagree.
static ONLINE: AtomicU32 = AtomicU32::new(1);

/// A place for a woken core to prove it can execute kernel code, not just reach
/// it: every core adds its own id, and the boot processor checks the total.
static ROLL_CALL: AtomicU64 = AtomicU64::new(0);

/// How many cores are running kernel code.
#[must_use]
pub fn online() -> u32 {
    ONLINE.load(Ordering::Acquire)
}

/// The sum every core contributed to, for the boot processor to check.
#[must_use]
pub fn roll_call() -> u64 {
    ROLL_CALL.load(Ordering::Acquire)
}

/// Where a woken core arrives, called from the trampoline with its APIC id.
///
/// It runs on a stack the boot processor allocated for it, with the kernel's page
/// tables and nothing else: no GDT of its own yet, no IDT, no local APIC enabled.
/// What it does here is deliberately the least that proves it is alive — anything
/// more would be a second thing that could fail, and then "the core did not come
/// up" would stop being a single claim.
///
/// # Safety
/// Entered once per core, by the trampoline, in long mode on the kernel's tables.
pub unsafe extern "C" fn ap_entry(cpu_id: u64) -> ! {
    ROLL_CALL.fetch_add(cpu_id + 1, Ordering::AcqRel);
    ONLINE.fetch_add(1, Ordering::AcqRel);

    // Halt with interrupts disabled. This core has no IDT, so an interrupt
    // arriving here would triple-fault the machine — and a core parked in `hlt`
    // is exactly what the scheduler will find when it is taught to hand out work.
    loop {
        // SAFETY: ring 0, and the core is meant to stop here.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// Copy the trampoline to its page, fill in the parameters, and identity-map it.
///
/// The identity mapping is the part that is easy to miss: between `mov cr0` and
/// the far jump that follows it, the core is executing at a *physical* address
/// with the kernel's paging live, so that address has to mean the same thing in
/// both worlds. Without it the machine triple-faults on the instruction after
/// paging is enabled, with no output and nothing to attribute it to.
///
/// # Safety
/// Called once, on the boot processor, with `tables` live and the linear map
/// covering low memory.
unsafe fn stage_trampoline(tables: &Tables, entry: u64) -> Result<(), &'static str> {
    let len = trampoline::blob_len();
    if len > PAGE_BYTES as usize - trampoline::PARAM_BASE {
        return Err("the trampoline outgrew its page");
    }

    // SAFETY: the blob is `.rodata` in this image; the destination is a physical
    // page below 1 MiB reached through the linear map, which the memory map marks
    // reserved and the frame pool therefore never hands out.
    unsafe {
        let src = &raw const trampoline::trampoline_start;
        let dst = phys_to_virt(TRAMPOLINE_PHYS) as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }

    // SAFETY: as above — a write through the linear map to a page this kernel
    // owns for the duration of bring-up.
    unsafe {
        let base = phys_to_virt(TRAMPOLINE_PHYS) as *mut u8;
        let put = |off: usize, value: u64| {
            base.add(off).cast::<u64>().write_volatile(value);
        };
        put(trampoline::params::CR3, tables.root);
        put(trampoline::params::ENTRY, entry);
        put(trampoline::params::ACK, 0);
    };

    // SAFETY: adding one identity mapping for a page the kernel controls, with
    // execute rights because a core is about to fetch instructions from it.
    unsafe {
        crate::vm::map_identity(
            tables,
            TRAMPOLINE_PHYS,
            PAGE_BYTES,
            staros_paging::Rights { write: true, exec: true, user: false },
        )
    }
}

/// Wake every core the firmware listed, and report how many answered.
///
/// # Safety
/// Called once, on the boot processor, after the APIC is up and `vm::init` has
/// run.
pub unsafe fn start_cores(
    console: &mut Console,
    tables: &Tables,
    facts: &Facts,
    lapic_phys: u64,
) -> u32 {
    if facts.cpus <= 1 {
        let _ = writeln!(console, "smp: 1 core in the MADT — nothing to wake");
        return 1;
    }

    // SAFETY: forwarded from this function's contract.
    let entry = (ap_entry as unsafe extern "C" fn(u64) -> !) as *const () as u64;
    // SAFETY: forwarded from this function's contract.
    if let Err(why) = unsafe { stage_trampoline(tables, entry) } {
        let _ = writeln!(console, "smp: {why}; staying single-core");
        return 1;
    }

    // A second window onto the local APIC, for this code to send with. Sharing
    // `irq`'s would mean holding its lock across the whole sequence — including
    // the ten-millisecond wait after INIT — while the timer interrupt it owns is
    // trying to take the same lock.
    // SAFETY: the MADT gave this address; it is already mapped uncacheable for
    // the driver in `irq`, and a second `LocalApic` over the same registers is
    // sound because every access below is a single volatile word.
    let Ok(virt) = (unsafe { crate::vm::map_device(tables, lapic_phys, 0x1000) }) else {
        let _ = writeln!(console, "smp: cannot map the local APIC; staying single-core");
        return 1;
    };
    // SAFETY: as above.
    let mut lapic = LocalApic::new(unsafe { MappedRegisters::new(virt) });
    let self_id = lapic.id();

    let page = u8::try_from(TRAMPOLINE_PHYS / PAGE_BYTES).unwrap_or(0);
    // Said before the first message goes out, not after the last one lands. Core
    // bring-up is the one sequence in this kernel that can wedge a machine without
    // faulting — a core that never answers leaves the boot processor waiting, and
    // a triple fault on the woken core resets the machine with no output at all.
    // A line here is the difference between "it stopped in bring-up" and "it
    // stopped somewhere after the timer".
    let _ = writeln!(
        console,
        "smp: waking {} core(s), trampoline at {TRAMPOLINE_PHYS:#x} ({} bytes), apic {self_id} is us",
        facts.cpus - 1,
        trampoline::blob_len(),
    );
    let mut woken = 0;
    for &id in facts.cpu_ids.iter().take(facts.cpus) {
        let Ok(target) = u8::try_from(id) else { continue };
        if target == self_id {
            continue;
        }
        // SAFETY: forwarded; the parameter block is the one staged above.
        unsafe { prepare_slot(id) };

        // Every command gets its own deadline, measured in time rather than in
        // spins of a loop. Ten milliseconds is far longer than an APIC needs to
        // accept a message and short enough that a core which will never accept
        // one is reported instead of waited on.
        // The sequence, with the delays the architecture manual specifies. They are
        // not padding: a core that has just taken INIT is resetting, and a startup
        // message arriving during that is missed rather than queued. The second
        // SIPI is sent unconditionally — a core that took the first ignores it, so
        // it costs nothing, and not sending it costs the one machine that needed
        // it.
        let sequence = lapic
            .send_init(target, &mut crate::irq::deadline_micros(IPI_TIMEOUT_MICROS))
            .and_then(|()| {
                lapic.send_init_deassert(
                    target,
                    &mut crate::irq::deadline_micros(IPI_TIMEOUT_MICROS),
                )
            })
            .and_then(|()| {
                crate::irq::stall_micros(10_000);
                lapic.send_startup(
                    target,
                    page,
                    &mut crate::irq::deadline_micros(IPI_TIMEOUT_MICROS),
                )
            })
            .and_then(|()| {
                crate::irq::stall_micros(200);
                lapic.send_startup(
                    target,
                    page,
                    &mut crate::irq::deadline_micros(IPI_TIMEOUT_MICROS),
                )
            });
        if sequence.is_none() {
            let _ = writeln!(console, "smp: apic {id} would not accept a message");
            continue;
        }

        // Wait for *this* core's acknowledgement before waking the next. Serial
        // bring-up costs a few milliseconds and buys a truthful report: with the
        // messages sent in a batch, one core failing to start is indistinguishable
        // from one core being slow, and the count would depend on how long the
        // boot processor felt like waiting.
        if wait_for_ack() {
            woken += 1;
        } else {
            let _ = writeln!(console, "smp: apic {id} did not reach kernel code");
        }
    }

    // The identity mapping goes as soon as every core has answered. It exists for
    // the two instructions between enabling paging and the far jump that follows,
    // and leaving it behind would mean a physical address below 1 MiB stays
    // executable for the life of the machine — the one place a stray pointer
    // could run instead of faulting.
    // SAFETY: every core that acknowledged is past the trampoline and running on
    // the kernel's own addresses; a core that never answered is not executing.
    unsafe { crate::vm::unmap_identity(tables, TRAMPOLINE_PHYS, PAGE_BYTES) };

    let total = online();
    let _ = writeln!(
        console,
        "smp: {total} core(s) online — {woken} woken of {} in the MADT, roll call {}",
        facts.cpus - 1,
        roll_call(),
    );
    total
}

/// Point the trampoline's parameter block at a fresh stack and the id it is for.
///
/// # Safety
/// The trampoline page must be staged, and no core may be using the block: cores
/// are woken one at a time, which is what makes that true.
unsafe fn prepare_slot(cpu_id: u32) {
    let stack_top = alloc_ap_stack().unwrap_or(0);
    // SAFETY: a write through the linear map to the staged page.
    unsafe {
        let base = phys_to_virt(TRAMPOLINE_PHYS) as *mut u8;
        base.add(trampoline::params::STACK_TOP).cast::<u64>().write_volatile(stack_top);
        base.add(trampoline::params::CPU_ID).cast::<u64>().write_volatile(u64::from(cpu_id));
        base.add(trampoline::params::ACK).cast::<u64>().write_volatile(0);
    }
}

/// Allocate a stack for a woken core and return its top, as a virtual address.
fn alloc_ap_stack() -> Option<u64> {
    // Contiguous, because a stack that crosses a hole is a stack that faults the
    // first time it grows past the first frame — and the fault would land on a
    // core with no IDT.
    let base = crate::mem::alloc_frames(AP_STACK_PAGES as usize)?;
    Some(phys_to_virt(base.0 as u64) + AP_STACK_PAGES * PAGE_BYTES)
}

/// Wait for the core just started to acknowledge, or give up.
fn wait_for_ack() -> bool {
    for _ in 0..200 {
        // SAFETY: reading the staged page through the linear map. Volatile,
        // because the value is written by another core and nothing in this loop
        // would otherwise make the compiler read it twice.
        let acked = unsafe {
            (phys_to_virt(TRAMPOLINE_PHYS) as *const u8)
                .add(trampoline::params::ACK)
                .cast::<u64>()
                .read_volatile()
        };
        if acked != 0 {
            return true;
        }
        crate::irq::stall_micros(1_000);
    }
    false
}
