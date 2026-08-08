# STAR OS Kernel — PC (x86_64)

The same microkernel as [`../kernel-new`](../kernel-new), on an ordinary PC.

Not a fork. The portable half — `abi`, `hal`, `mm`, `ipc`, `cpio`,
`framebuffer`, `drivers` — is the **same code**, addressed by path into
`../kernel-new/crates`. A second architecture is the only honest test of whether
the HAL boundary is real, and a copy would fail that test on day one by letting
the two drift.

## Layout

| Crate | Role |
|-------|------|
| `crates/acpi` | ACPI tables — the PC's device tree. RSDP, XSDT/RSDT, MADT, MCFG, HPET. No MMIO, no AML |
| `crates/bootinfo` | The loader → kernel hand-off contract: memory map, framebuffer, RSDP, initramfs, and the address-space layout both binaries agree on |
| `crates/elf64` | ELF64 program headers — how the loader reads a kernel image |
| `crates/boot-uefi` | The UEFI loader: firmware bindings, ESP access, page tables, `ExitBootServices` |
| `crates/arch-x86_64` | I/O ports, 16550 UART, CPU control, GDT/IDT/TSS, trap entry, 8259/8254, APIC, HPET, context switch, `syscall`/`sysret`. SMP is scheduled, not stubbed |
| `crates/kernel` | The privileged binary |

Two binaries, two targets, on purpose: the loader is PE/COFF for firmware, the
kernel is ELF for hardware. `docs/SPEC.md` §2.1 explains why they cannot be one —
the firmware's ABI stops existing at `ExitBootServices`.

## Build & test

```bash
cargo kbuild        # kernel ELF   -> x86_64-unknown-none
cargo kloader       # loader EFI   -> x86_64-unknown-uefi
cargo kclippy       # clippy, kernel
cargo kloader-clippy
cargo ktest-host    # the crates this tree owns (192 tests)

./scripts/mkesp.sh       # build both halves, stage an ESP layout
./scripts/run-qemu.sh    # boot it: OVMF -> BOOTX64.EFI -> kernel
./scripts/smoke-test.sh  # boot it and assert on the output (99 assertions)
./scripts/boot-matrix.sh # boot it on six other machines (196 assertions)
```

Shared crates are tested in `../kernel-new` (`cargo ktest-host` there), so their
102 tests are not duplicated here.

`mkesp.sh --to /path/to/mounted/esp` writes the same layout onto a real EFI
partition; `run-qemu.sh --debug` starts stopped with a gdb stub on `:1234`.

## Status

**Phases 1 and 2 complete, and phase 3.1, verified on live firmware.** OVMF
finds `EFI/BOOT/BOOTX64.EFI`; the loader collects the RSDP, the GOP framebuffer,
the kernel and an optional initramfs off the ESP it was itself loaded from, places
the `PT_LOAD` segments with their own rights (W^X), builds identity, linear and
kernel mappings, takes the memory map last, leaves boot services with the retry
the specification requires, and jumps to `_start` with `BootInfo` in `RDI`. The
kernel takes its own stack, validates the hand-off, mirrors every message to COM1
and the screen, installs its own GDT, TSS and IDT, takes ownership of physical
memory, builds its own page tables, moves the 8259s off the CPU's exception
vectors, reads the interrupt topology out of ACPI, brings up the APICs,
calibrates its own timer against the HPET, runs two kernel threads that share the
CPU without either of them asking to, and drops into ring 3 to run a program it
does not trust — and proves each of those by faulting, interrupting, measuring or
preempting on purpose, because a correct table and a subtly wrong one are both
completely silent until something happens.

```
STAR OS microkernel (x86_64) v0.1.0
boot info accepted: 30 memory regions, rsdp 0x1fb7e014, kernel 0x1d999000+0x54000
framebuffer: 1280x800 stride 5120 at 0x80000000 (4000 KiB)
console: mirroring to the screen (readback self-test passed)
gdt: loaded, kernel cs 0x08 ss 0x10, tss 0x30
idt: 256 vectors, separate stacks for #DF, NMI and #MC
trap: #BP at RIP=0xffffffff80017311, resuming
trap: #PF at 0xffffffff80043000, err=0x0 (read from an unmapped page), resuming
memory: 13059 MiB described, 458 MiB usable, RAM tops out at 0x20000000
memory: device apertures reach 0x10000000000; the linear map stops at RAM
memory: heap 1940 KiB at 0x1780000, pool 455 MiB over 11 run(s) in 39 tree(s), 116647 frames managed
vm: verified - text 0xffffffff800069a0 r-x, rodata r--, data rw-, 0x0 and the guard page absent
vm: cr3 0x1900000, linear 4 GiB (1 GiB pages), smep on, smap on
trap: #PF at 0x0, RIP=0xffffffff800172b8, err=0x0 (read from an unmapped page)
smap: the write faulted and did not happen
smap: stac opened the hole, the same write succeeded
frames: 4 rounds of up to 64 allocations converged
pic: 8259 pair remapped to vectors 32..48, masks 0xffff
pit: channel 0 at 1000 Hz on IRQ 0, expecting vector 32
irq: 8 timer interrupts delivered on vector 32 and acknowledged
irq: interrupts masked again until the APIC is up
acpi: madt at 0x1fb78000, 1 cpu(s), local apic at 0xfee00000, legacy pics present
acpi: io apic at 0xfec00000, first gsi 0
acpi: hpet at 0xfed00000
lapic: id 0, version 0x14, 6 lvt entries, spurious vector 255, enabled
ioapic: id 0, version 0x20, 24 entries covering gsi 0..24
ioapic: irq 0 arrives on gsi 2 (remapped by the MADT - assuming identity would route the wrong line)
ioapic: gsi 2 -> vector 48 on apic 0, pit at 1000 Hz
irq: 8 timer interrupts delivered on vector 48 through the I/O APIC and acknowledged at the local APIC
hpet: 100000000 Hz (10000000 fs per tick), 3 comparators, 64-bit counter, vendor 0x8086
lapic timer: 62483087 ticks/s at divisor 16, measured over 20 ms of HPET
lapic timer: periodic, 624830 ticks per interrupt on vector 49 (100 Hz nominal)
timer: 100 interrupts at 100 Hz took 1.000 s by the HPET (0.0% off, tolerance 2%)
sched: 2 tasks, 32 KiB of kernel stack each, round robin
sched: preempting at 100 Hz, each task runs for 30 ticks and exits
task A: 10 ticks in, 291584 steps, saw the other move 5 times
task B: 10 ticks in, 310039 steps, saw the other move 5 times
task A: done after 845497 steps
task B: done after 917498 steps
sched: 33 switches (30 forced by the timer), 2 of 2 tasks finished
sched: A took 845497 steps and saw B move 14 times; B took 917498 steps and saw A move 14 times
sched: 2 dead stacks reaped, 64 KiB returned to the heap
syscall: enabled, entry 0xffffffff8002a424, kernel cs 0x08, sysret cs 0x2b ss 0x23, fmask 0x54700
user: 173 byte program at 0x400000 r-x, stack 0x7ffff000 rw-, clock 0x410000 r--
user: hello from ring 3
user: preempted while in ring 3, yielded, and came back
user: 4 syscalls served (0 refused), 80 bytes written, 1 voluntary switch(es)
user: 16 timer interrupts arrived from ring 3 at 100 Hz (they used TSS.rsp0, nothing else could have)
sysret: forcing a non-canonical return address (0x800000000000) on the program's first syscall
user fault: task "N" took vector 13 - #GP general protection fault in ring 3
  RIP=0x0000800000000000 CS=0x002b RSP=0x000000007ffffff8 SS=0x0023 error=0x0
  killing the task; the kernel continues
phase 3.1 complete: code the kernel does not trust ran, and came back.

KERNEL FAULT: vector 8 - #DF double fault
  the first fault was at 0xffffffff80043f68
  that is the kernel stack guard page: the stack overflowed
```

Every one of those faults is deliberate and each answers a question the log
cannot otherwise settle. `int3` and the page fault cover both shapes of interrupt
stub — one vector with an error code and one without — and both return through
`iretq`. The null dereference is the phase-1.3 criterion that could only be met in
1.4: until the kernel built its own tables, the loader's identity map made
address zero ordinary RAM, and reading it returned a value. The SMAP test checks
not only that the write faulted but that it *did not happen*, by reading the page
back through the linear map — a SMAP that was never enabled produces no fault, no
message, and a successful store, which is indistinguishable from success in a
log. And the last one overflows the stack into its guard page: the report exists
only because `#DF` is delivered on its own IST stack. Remove that one line and the
log stops mid-sentence with a triple fault.

The timer ticks are the same kind of evidence. Firmware leaves the 8259 pair
delivering on vectors 0 through 15, which belong to the CPU's exceptions, and the
chips' vector base is write-only — there is no way to ask them where they are
delivering. So the kernel remaps them, masks everything, starts the 8254, and
counts. Eight ticks rather than one, because one proves delivery and not
acknowledgement: without an EOI the line stays in service and the second never
comes. Skip the remap and that same tick arrives as vector 0, ending the boot in
`KERNEL FAULT: vector 0 - #DE divide error` — a division that never happened,
which is exactly the class of lie the remap exists to prevent.

The second set of ticks proves something different: that the route was *read*
rather than guessed. The I/O APIC has one redirection entry per **global system
interrupt**, and legacy IRQ numbers map onto GSIs by a table the firmware
publishes — not by identity. On this machine the timer's IRQ 0 arrives as GSI 2,
because the 8259 cascade line took GSI 0 first. Program entry 0 and the line is
configured perfectly for something that is not attached to it: no error, no fault,
no ticks. The entry is also read back after writing, because these are indirect
registers — an index to one port, a value to another — and a driver with the
sequence wrong writes somewhere plausible and reports nothing.

That phase is also where the shared HAL's interrupt trait had to be reshaped, which
is the whole reason a second architecture exists in this repository.
`acknowledge()` used to be one of its four methods: on a GIC it both identifies the
pending interrupt and takes it, because the handler asks `GICC_IAR` and the register
answers with an id. There is no such register on x86 and no such question — the I/O
APIC was told in advance which vector the line becomes, so by the time the handler
runs the CPU has already answered by choosing an IDT entry. A method whose purpose
is to ask cannot be implemented by a controller that was told, so it moved into
`AcknowledgingController`, which the GIC implements and the APIC does not.
`end_of_interrupt` kept its argument and gained a paragraph saying it is advisory:
the local APIC's EOI register accepts only zero, the GIC's needs the id, and an
implementation that ignores an argument loses nothing while one that needs a
missing argument is broken.

The last line of that block is a different kind of check again. Every clock on
this machine has to be measured before it can be trusted — the APIC timer counts
at the bus frequency, which varies by machine and by power state and is written
down nowhere. The HPET is the exception: its capability register states the period
of one tick in femtoseconds, so it needs no calibration and everything else is cut
against it. A hundred ticks at a hundred hertz must then take a second, to within
two per cent, timed by the clock that was not involved in producing them.

That tolerance is what makes it a test rather than a presence check. A calibration
that read the wrong register, or divided in the wrong direction, or used the
APIC's divide encoding as though it were a logarithm — it is not; bit 2 is
reserved and divide-by-one sits *past* the whole range — still produces a timer
that ticks perfectly steadily, forever, at the wrong rate. Only a second clock can
tell. Making `ticks_to_ns` divide by a thousand instead of a million reports the
error as 6036%, and the boot declines to claim the phase.

The two tasks at the end are a different question again, and the interesting part
is what the obvious criterion would have missed. Neither task yields — they spin,
count, and exit after thirty ticks — so **both of them finish whether or not
preemption works**, one strictly after the other if it does not. "Two of two tasks
finished" is therefore not evidence of anything. What only preemption can produce
is each task *observing the other advance while it was itself running*: that
requires the other to have run in between, and nothing in either body asked for
it. Both counts have to be non-zero, since one alone would just be a task that
started late and looked at a finished neighbour. Deleting the one line that asks
for a reschedule from the timer tick leaves the log reporting two finished tasks,
three switches, and `saw the other move 0 times` — a pass under the naive
criterion and a failure under this one.

Starting a task at all is where x86 differs from the sibling tree in the one way
that is not a simplification. Six callee-saved registers instead of nineteen is
genuinely less work; but AArch64 has a link register, so bootstrapping a task
there means writing the trampoline's address into the saved `x30`. Here `ret`
takes its target off the stack, so the task's first frame has to be *built* —
which makes the alignment the System V ABI requires something the code must
establish rather than inherit, and makes a mistake in it wait silently for the
first `movaps` some unrelated code grows a local wide enough to need. That word is
placed by a function with no `unsafe` in it and seven host tests around it.

The 64 KiB on the last line is the check that would have been easiest to leave
out. A task cannot free the stack it is standing on, so its successor does it, and
the successor is not obviously anyone's responsibility. Removing that hand-off
changes nothing anyone would notice: thirty preemptions, perfect interleaving,
both tasks finished, every other assertion green — and 64 KiB gone until reboot.
The only way to see it is to require that what was created came back.

Ring 3 is where this port stops resembling the sibling tree at all. On AArch64
`svc` is an exception: it goes through the same vectors as every other trap, the
hardware switches to `SP_EL1` by itself, and the return address and flags land in
system registers the kernel can read whenever it likes. `syscall` is not an
exception — it is a jump that loads `RIP` and `CS`/`SS` from MSRs, destroys `RCX`
and `R11` by putting the return address and flags in them (which is why the fourth
syscall argument is `R10`), clears whichever flags `IA32_FMASK` names, and does
**nothing to `RSP`**. The kernel begins executing with ring-3 privilege gone and
the ring-3 *stack* still in `RSP`, and every register still belonging to the
caller, so there is nowhere to put it — which is what `swapgs` and a per-core block
are for.

`GS` then turns out to be state belonging to the *core*, not to the task, and that
distinction cost a debugging session. The stub swaps in and swaps out, which
balances for any syscall that returns. A handler that switches tasks in the middle
— a `Yield`, or an `Exit` that never comes back — leaves the core running somebody
else's code with the kernel base still in `GS`. Nothing in ring 0 reads `GS`, so it
looks harmless. The *next* syscall, from any task, swaps again and gets the user's
base, and the instruction after that writes through it: a `#PF` inside the entry
stub, on a user stack, at an address that means nothing, two tasks after the
mistake.

`TSS.rsp0` is the field with no alternative. A syscall's kernel stack can be
handed over through `GS` because the kernel writes the entry stub; an *interrupt*
is delivered by the CPU, which reads `rsp0` out of the TSS before one kernel
instruction runs. So the boot log's count of "timer interrupts that arrived from
ring 3" is the only evidence that field is right — an interrupt taken in ring 0
changes no stack, so a kernel thread being preempted a thousand times proves
nothing. Blank that write and the first tick in ring 3 is a double fault.

The last check in that block is one the test bench cannot demonstrate, which is
worth saying plainly. `sysretq` takes `RIP` from `RCX`, and on **Intel** silicon a
non-canonical value raises `#GP` inside the instruction — before the privilege
change, in ring 0, at an address ring 3 chose. On AMD it is not checked at all and
the fault happens on the instruction fetch in ring 3, harmlessly. QEMU's
interpreter follows AMD whatever CPU model is asked for, so deleting the check from
this kernel and booting produces an identical log: `#GP` in ring 3, task killed,
every assertion green. A mitigation that cannot be seen working is one nobody
notices the removal of, so the boot asserts on the *decision* instead — that one
return went out through `iretq` rather than `sysretq` — which is false the moment
the check is gone, on any machine.

`DebugWrite` is the syscall that made the rest of it necessary. It takes a pointer
into ring 3's memory, so the kernel has to answer two questions it had never faced:
whether the caller may read that address, and how ring 0 reads it at all with SMAP
on. The first is a page-table *walk*, not a range check — being in the user half
proves only that an address is not the kernel's, and dereferencing an unmapped or
supervisor-only one from ring 0 is a fault in the kernel. The second is `stac`
around the copy and `clac` after it, a window exactly as wide as the copy. That
`stac` is conditional, and not for speed: on a CPU without SMAP it is not a no-op
but an invalid opcode, which is how `-cpu qemu64` in the boot matrix earns its
place twice over.

The page tables themselves are not checked by booting. `staros-paging` abstracts
the two things the loader and the kernel do differently — where a table frame
comes from, and how a physical address is reached to write it — so the walk is
ordinary logic. On the host it builds trees over a `Vec` of fake pages and takes
them apart again with `translate()`, which returns the rights **the walk**
computes rather than the leaf's: the AND of the write and user bits and the OR of
the NX bits, which is what the CPU enforces and where the invisible mistakes are.

Before `mov cr3` the kernel walks its new tree and refuses to load one that gets
anything wrong — the code doing the switch unmapped, a writable text section, a
mapping at address zero. That instruction has no failure mode short of a triple
fault, so the check has to happen while there is still a console to complain to.

The screen is checked, not assumed: `run-qemu.sh --screenshot` dumps a frame
through the QEMU monitor and `scripts/check-screen.py` counts lit pixels and
compares colours. It expects a `33ff66` foreground — `Rgb::GREEN`, the one stock
colour whose red and blue channels differ, so an inverted pixel-format mapping
would render `66ff33` and nothing else would ever notice — and it requires the
fault report's `ff3333` to be on the panel too. On a machine with no serial port
the screen is the only place a fault can be seen, and phase 3's board is exactly
that machine.

`smoke-test.sh` also breaks the input on purpose — the aarch64 kernel on the
ESP, a truncated image, no image at all — and checks each is refused by name and
halts rather than falling through to the next boot option. A loader that has only
ever seen a good kernel is a loader whose error paths have never run.

`boot-matrix.sh` asks the other question: does it work on a machine that is not
this one. Six more configurations, each chosen because it runs code the default
QEMU machine never reaches — and each asserting on what should be *different*,
not merely that the boot finished.

| machine | what it is the only test of |
|---|---|
| `-cpu qemu64` | the 2 MiB page-table fallback, and the no-SMEP/SMAP branch |
| `-m 128M` | a heap that is a visible fraction of the machine |
| `-m 4G` | RAM either side of the PCI hole, so the extent of RAM is not the amount of it |
| `-vga none` | no GOP at all: the console is serial only and every framebuffer path is absent |
| `-smp 4` | three cores parked by firmware while the boot core rewrites `CR3` and `CR4` |
| `-machine pc` | a different chipset, so the memory map is read rather than recognised |
| `--release` | LTO and `opt-level = "z"` over naked functions, inline assembly and a linker script |

The 4 GiB machine earned its place by making a real limitation visible, and it
now guards the fix. The frame pool used to be a *single* contiguous run handed to
a *single* buddy tree, which rounds down to a power of two — so a guest reporting
4041 MiB usable, split around the PCI hole into a largest run of 1956 MiB, ended
up managing 1024 MiB. A quarter of the machine, asserted by this matrix and
thereby made visible without being made acceptable.

It takes every free run now, and `staros_mm::FramePool` decomposes each into its
binary expansion — 1956 frames becomes 1024 + 512 + 256 + 128 + 32 + 4, one buddy
tree per piece — so nothing is rounded away. The same guest manages 4032 MiB, and
the kernel computes what it *failed* to manage and prints it, which the matrix
forbids ever appearing. The price is metadata: four times as many frames tracked
at 8 bytes each, so the heap goes from 3 MiB to 9 MiB. That is 0.2% of the memory
it makes usable.

What survives is stated rather than hidden: an allocation is served by one tree
or refused, never stitched across two, because the frames would not be contiguous
and contiguity is the only reason to ask for more than one frame at a time.

[`docs/SPEC.md`](docs/SPEC.md) holds the contracts: boot hand-off, memory layout,
interrupt model, syscall ABI, and every place x86 differs from aarch64 along with
why.

Nothing here is stubbed to look finished: a function that returns `Ok` without
doing the work is worse than an absent one, because the boot log then claims a
subsystem that was never written.
