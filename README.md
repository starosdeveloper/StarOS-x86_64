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
cargo ktest-host    # the crates this tree owns (95 tests)

./scripts/mkesp.sh       # build both halves, stage an ESP layout
./scripts/run-qemu.sh    # boot it: OVMF -> BOOTX64.EFI -> kernel
./scripts/smoke-test.sh  # boot it and assert on the output (44 assertions)
```

Shared crates are tested in `../kernel-new` (`cargo ktest-host` there), so their
89 tests are not duplicated here.

`mkesp.sh --to /path/to/mounted/esp` writes the same layout onto a real EFI
partition; `run-qemu.sh --debug` starts stopped with a gdb stub on `:1234`.

## Status

**Phase 1.3 complete, verified on live firmware.** OVMF finds
`EFI/BOOT/BOOTX64.EFI`; the loader collects the RSDP, the GOP framebuffer, the
kernel and an optional initramfs off the ESP it was itself loaded from, places
the `PT_LOAD` segments with their own rights (W^X), builds identity, linear and
kernel mappings, takes the memory map last, leaves boot services with the retry
the specification requires, and jumps to `_start` with `BootInfo` in `RDI`. The
kernel takes its own stack, validates the hand-off, mirrors every message to COM1
and the screen, installs its own GDT, TSS and IDT — and then faults three times
on purpose, because a correct interrupt table and a subtly wrong one are both
completely silent until something faults.

```
STAR OS loader v0.1.0 (x86_64 UEFI)
acpi: rsdp at 0x1fb7e014
gop: 1280x800 stride 5120 at 0x80000000
esp: kernel 2990 KiB at 0x1dac4000
kernel: 252 KiB placed at 0x1da85000, mapped at 0xffffffff80000000, entry 0xffffffff80000000
paging: 4 GiB identity + linear at 0xffff800000000000 (1 GiB pages), kernel W^X
handoff: 30 regions, entry 0xffffffff80000000, boot info at 0x1ddf3000

STAR OS microkernel (x86_64) v0.1.0
boot info accepted: 30 memory regions, rsdp 0x1fb7e014, kernel 0x1da85000+0x3f000
framebuffer: 1280x800 stride 5120 at 0x80000000 (4000 KiB)
console: mirroring to the screen (readback self-test passed)
gdt: loaded, kernel cs 0x08 ss 0x10, tss 0x30
idt: 256 vectors, separate stacks for #DF, NMI and #MC
trap self-test: int3
trap: #BP at RIP=0xffffffff800077a1, resuming
trap self-test: reading the unmapped guard page at 0xffffffff8002e000
trap: #PF at 0xffffffff8002e000, RIP=0xffffffff800077c8, err=0x0 (read from an unmapped page), resuming at 0xffffffff800077cb
trap self-test: both traps returned to their caller
phase 1.3 complete: own stack, hand-off verified, console up, faults caught.
trap self-test: overflowing the kernel stack into its guard page at 0xffffffff8002e000

KERNEL FAULT: vector 8 - #DF double fault
  RIP=0xffffffff800077d8 CS=0x0008 RFLAGS=0x82
  RSP=0xffffffff8002efe0 SS=0x0010 error=0x0 ring=0
  the first fault was at 0xffffffff8002efd8
  that is the kernel stack guard page: the stack overflowed
  halting - this core cannot continue
```

The three are chosen to cover what nothing else can reach. `int3` is a vector
with no error code; the page fault is one with, so between them both shapes of
entry stub run, and both come back through `iretq`. The address read is the
stack guard page rather than zero — the loader still identity-maps the low 4 GiB,
so a null dereference reads real memory until phase 1.4 — which also proves the
guard is genuinely unmapped, the assumption the last test rests on. That last one
overflows the stack into the guard page on purpose: the report is only possible
because `#DF` is delivered on its own IST stack. Remove that one line and the log
stops mid-sentence with a triple fault.

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

[`docs/SPEC.md`](docs/SPEC.md) holds the contracts: boot hand-off, memory layout,
interrupt model, syscall ABI, and every place x86 differs from aarch64 along with
why.

Nothing here is stubbed to look finished: a function that returns `Ok` without
doing the work is worse than an absent one, because the boot log then claims a
subsystem that was never written.
