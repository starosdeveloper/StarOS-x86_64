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
| `crates/arch-x86_64` | I/O ports, 16550 UART, CPU control. GDT/IDT, paging, APIC and SMP are scheduled, not stubbed |
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
cargo ktest-host    # the crates this tree owns (149 tests)

./scripts/mkesp.sh       # build both halves, stage an ESP layout
./scripts/run-qemu.sh    # boot it: OVMF -> BOOTX64.EFI -> kernel
./scripts/smoke-test.sh  # boot it and assert on the output (73 assertions)
./scripts/boot-matrix.sh # boot it on six other machines (123 assertions)
```

Shared crates are tested in `../kernel-new` (`cargo ktest-host` there), so their
89 tests are not duplicated here.

`mkesp.sh --to /path/to/mounted/esp` writes the same layout onto a real EFI
partition; `run-qemu.sh --debug` starts stopped with a gdb stub on `:1234`.

## Status

**Phase 1 complete, and phase 2 through 2.2, verified on live firmware.** OVMF
finds `EFI/BOOT/BOOTX64.EFI`; the loader collects the RSDP, the GOP framebuffer,
the kernel and an optional initramfs off the ESP it was itself loaded from, places
the `PT_LOAD` segments with their own rights (W^X), builds identity, linear and
kernel mappings, takes the memory map last, leaves boot services with the retry
the specification requires, and jumps to `_start` with `BootInfo` in `RDI`. The
kernel takes its own stack, validates the hand-off, mirrors every message to COM1
and the screen, installs its own GDT, TSS and IDT, takes ownership of physical
memory, builds its own page tables, moves the 8259s off the CPU's exception
vectors, reads the interrupt topology out of ACPI and brings up the APICs — and
proves each of those by faulting or interrupting on purpose, because a correct
table and a subtly wrong one are both completely silent until something happens.

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
memory: heap 1536 KiB at 0x1780000, pool 422 MiB at 0x1900000 (65536 frames managed)
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
lapic: id 0, version 0x14, 6 lvt entries, spurious vector 255, enabled
ioapic: id 0, version 0x20, 24 entries covering gsi 0..24
ioapic: irq 0 arrives on gsi 2 (remapped by the MADT - assuming identity would route the wrong line)
ioapic: gsi 2 -> vector 48 on apic 0, pit at 1000 Hz
irq: 8 timer interrupts delivered on vector 48 through the I/O APIC and acknowledged at the local APIC
phase 2.2 complete: interrupts routed by the APICs, on the vectors ACPI named.

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

The 4 GiB machine is the one that makes a current limitation visible, so the
matrix asserts on it rather than letting it pass unnoticed: the frame pool is a
single contiguous run, and the buddy allocator rounds that run down to a power of
two. A 4 GiB guest reports 4042 MiB usable, splits it around the PCI hole so the
largest run is 1956 MiB, and the allocator manages 1024 MiB of that — about a
quarter of the machine. Not a bug, but not free either, and the line that has to
change when one pool becomes several.

[`docs/SPEC.md`](docs/SPEC.md) holds the contracts: boot hand-off, memory layout,
interrupt model, syscall ABI, and every place x86 differs from aarch64 along with
why.

Nothing here is stubbed to look finished: a function that returns `Ok` without
doing the work is worse than an absent one, because the boot log then claims a
subsystem that was never written.
