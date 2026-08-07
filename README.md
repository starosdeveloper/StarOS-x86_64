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
| `crates/bootinfo` | The loader → kernel hand-off contract: memory map, framebuffer, RSDP, initramfs |
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
cargo ktest-host    # the crates this tree owns (68 tests)

./scripts/mkesp.sh      # build both halves, stage an ESP layout
./scripts/run-qemu.sh   # boot it: OVMF -> BOOTX64.EFI -> kernel
```

Shared crates are tested in `../kernel-new` (`cargo ktest-host` there), so their
89 tests are not duplicated here.

`mkesp.sh --to /path/to/mounted/esp` writes the same layout onto a real EFI
partition; `run-qemu.sh --debug` starts stopped with a gdb stub on `:1234`.

## Status

**Phase 1.1 written, not yet verified on live firmware.** The loader collects the
RSDP, the GOP framebuffer, the kernel and an optional initramfs off the ESP it
was itself loaded from, places the `PT_LOAD` segments with their own rights
(W^X), builds identity, linear and kernel mappings, takes the memory map last,
leaves boot services with the retry the specification requires, and jumps to
`_start` with `BootInfo` in `RDI`. The kernel takes its own stack, validates the
hand-off and reports it.

What has *not* happened is a boot: this machine has neither `qemu-system-x86_64`
nor OVMF, so no firmware has ever run this loader. 68 host tests pass, both
targets build, clippy is clean on both — and none of that is the same as a
character on a screen. The two commands that would settle it are in
[`docs/ROADMAP.md`](docs/ROADMAP.md) §1.1.

[`docs/SPEC.md`](docs/SPEC.md) holds the contracts: boot hand-off, memory layout,
interrupt model, syscall ABI, and every place x86 differs from aarch64 along with
why.

Nothing here is stubbed to look finished: a function that returns `Ok` without
doing the work is worse than an absent one, because the boot log then claims a
subsystem that was never written.
