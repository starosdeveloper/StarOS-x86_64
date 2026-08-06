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
| `crates/arch-x86_64` | I/O ports, 16550 UART, CPU control. GDT/IDT, paging, APIC and SMP are scheduled, not stubbed |
| `crates/kernel` | The privileged binary |

## Build & test

```bash
cargo kbuild        # kernel ELF for x86_64-unknown-none
cargo kclippy       # clippy across the kernel
cargo ktest-host    # the crates this tree owns (35 tests)
```

Shared crates are tested in `../kernel-new` (`cargo ktest-host` there), so their
89 tests are not duplicated here.

## Status

**Phase 0 complete** — workspace, target, higher-half linker script, two
host-tested crates, a minimal arch layer, and an entry point that validates the
hand-off and reports what it got.

The kernel links at `0xFFFFFFFF80000000` and halts after reporting; it has no
loader yet, so it does not boot. That is phase 1.1 — see
[`docs/ROADMAP.md`](docs/ROADMAP.md) for the sequence and
[`docs/SPEC.md`](docs/SPEC.md) for the contracts (boot hand-off, memory layout,
interrupt model, syscall ABI, and every place x86 differs from aarch64 along with
why).

Nothing here is stubbed to look finished: a function that returns `Ok` without
doing the work is worse than an absent one, because the boot log then claims a
subsystem that was never written.
