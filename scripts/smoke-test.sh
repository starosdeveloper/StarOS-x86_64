#!/usr/bin/env bash
# Boot STAR OS under OVMF and assert on what comes out.
#
# The counterpart to ../kernel-new/scripts/smoke-test.sh, and the same discipline:
# assert on the lines that must appear *and* on the ones that must not, then
# deliberately break the input and check that the failure is named correctly.
# A loader that only ever runs against a good kernel is a loader whose error
# paths have never executed.
#
# The negative cases are the interesting half. Each one is a mistake that is easy
# to make and, without a named message, presents as a machine that does nothing:
# the aarch64 kernel copied onto a PC's ESP, a half-written file, no kernel at all.
set -euo pipefail

cd "$(dirname "$0")/.."

TIMEOUT="${TIMEOUT:-60}"
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

PASS=0
FAIL=0

# Assert that a pattern does (or does not) appear in a log.
expect() {
    local log="$1" what="$2" pattern="$3"
    if grep -qE -- "$pattern" "$log"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  MISSING: $what" >&2
        echo "           expected /$pattern/" >&2
    fi
}
forbid() {
    local log="$1" what="$2" pattern="$3"
    if grep -qE -- "$pattern" "$log"; then
        FAIL=$((FAIL + 1))
        echo "  PRESENT BUT FORBIDDEN: $what" >&2
        grep -nE -- "$pattern" "$log" | head -3 >&2
    else
        PASS=$((PASS + 1))
    fi
}

boot() {
    local log="$1"
    shift
    # The kernel halts rather than exiting, so QEMU never returns on its own;
    # the timeout *is* the end of the run, not a failure.
    timeout "$TIMEOUT" ./scripts/run-qemu.sh --headless "$@" > "$log" 2>&1 || true
}

# Assert on the captured screen. Delegated to a real file rather than inlined:
# the check is a dozen lines of byte comparison, and a shell here-doc is a bad
# place to keep anything containing backslash escapes.
check_screen() {
    local ppm="$1"
    if [ ! -s "$ppm" ]; then
        FAIL=$((FAIL + 1))
        echo "  NO SCREENSHOT: the QEMU monitor produced nothing" >&2
        return
    fi
    local out
    if out=$(python3 ./scripts/check-screen.py "$ppm" 2>&1); then
        PASS=$((PASS + 1))
        echo "  screen: $out"
    else
        FAIL=$((FAIL + 1))
        echo "  SCREEN CHECK FAILED: $out" >&2
    fi
}

echo "==> staging"
./scripts/mkesp.sh > /dev/null
GOOD="$LOG_DIR/kernel.good"
cp target/esp/staros/kernel "$GOOD"

# --------------------------------------------------------------------------
echo "==> [good] firmware -> loader -> kernel"
boot "$LOG_DIR/good.log" --screenshot "$LOG_DIR/screen.ppm"
L="$LOG_DIR/good.log"

expect "$L" "loader announces itself"        'STAR OS loader v[0-9]'
expect "$L" "RSDP found in the EFI config table" 'acpi: rsdp at 0x[0-9a-f]+'
forbid "$L" "no RSDP"                        'WARNING - no RSDP'
expect "$L" "GOP reports a linear framebuffer" 'gop: [0-9]+x[0-9]+ stride [0-9]+ at 0x'
expect "$L" "kernel read off the ESP"        'esp: kernel [0-9]+ KiB at 0x'
expect "$L" "segments placed at the linked base" 'kernel: .* mapped at 0xffffffff80000000'
expect "$L" "entry is the linked entry"      'entry 0xffffffff80000000'
expect "$L" "linear map at the specified base" 'linear at 0xffff800000000000'
expect "$L" "kernel image mapped W\\^X"      'kernel W\^X'
# A high device aperture must not stretch the map. q35 parks 12 GiB of reserved
# space at 1012 GiB; counting it built 1024 GiB of mappings.
forbid "$L" "map stretched by a device aperture" 'paging: [0-9]{3,} GiB'
expect "$L" "1 GiB pages used where the CPU has them" '\(1 GiB pages\)'
expect "$L" "hand-off built"                 'handoff: [0-9]+ regions'

expect "$L" "kernel reached its own entry"   'STAR OS microkernel \(x86_64\)'
expect "$L" "hand-off validated by the kernel" 'boot info accepted: [0-9]+ memory regions'
expect "$L" "kernel sees the framebuffer"    'framebuffer: [0-9]+x[0-9]+ stride'
expect "$L" "screen attached, readback verified" 'console: mirroring to the screen \(readback self-test passed\)'
forbid "$L" "screen described but unusable"  'console: screen unusable'
expect "$L" "boot reached the end of phase 1.2" 'phase 1.2 complete'

# What a serial log cannot answer: was anything drawn, and in the right colours.
check_screen "$LOG_DIR/screen.ppm"

forbid "$L" "loader failure"                 'BOOT FAILED'
forbid "$L" "kernel panic"                   'KERNEL PANIC'
forbid "$L" "rejected hand-off"              'boot info rejected'
forbid "$L" "null boot info"                 'null boot info pointer'
# Both halves write to COM1, but never at the same time: while ConOut is alive
# the firmware mirrors it there itself, and driving the UART as well printed
# every character twice, interleaved at the flush boundary.
forbid "$L" "doubled output (console driven twice)" 'acpi: rsdp at acpi:'

# --------------------------------------------------------------------------
echo "==> [wrong arch] the aarch64 kernel on a PC's ESP"
AARCH64="../kernel-new/target/aarch64-unknown-none/debug/kernel"
if [ -f "$AARCH64" ]; then
    cp "$AARCH64" target/esp/staros/kernel
    boot "$LOG_DIR/arch.log"
    expect "$LOG_DIR/arch.log" "wrong machine is named, not just refused" 'BOOT FAILED: wrong machine'
    forbid "$LOG_DIR/arch.log" "kernel entered anyway" 'STAR OS microkernel'
else
    echo "  skipped: build ../kernel-new first (cargo kbuild there) to cover this"
fi

# --------------------------------------------------------------------------
echo "==> [truncated] a half-written kernel image"
head -c 40000 "$GOOD" > target/esp/staros/kernel
boot "$LOG_DIR/trunc.log"
expect "$LOG_DIR/trunc.log" "truncation caught by the ELF walk" 'BOOT FAILED: segment lies outside the file'
forbid "$LOG_DIR/trunc.log" "kernel entered anyway" 'STAR OS microkernel'

# --------------------------------------------------------------------------
echo "==> [absent] no kernel on the ESP"
rm -f target/esp/staros/kernel
boot "$LOG_DIR/absent.log"
expect "$LOG_DIR/absent.log" "missing kernel is reported as such" 'BOOT FAILED: open kernel'
forbid "$LOG_DIR/absent.log" "kernel entered anyway" 'STAR OS microkernel'

# Every failure path must stop, not fall through to the next boot option — a
# loader that returns hands the machine to the firmware's boot menu and the
# message explaining why scrolls away.
for f in arch trunc absent; do
    [ -f "$LOG_DIR/$f.log" ] || continue
    expect "$LOG_DIR/$f.log" "[$f] halts instead of returning" 'halting - the kernel was not entered'
done

cp "$GOOD" target/esp/staros/kernel

echo
if [ "$FAIL" -eq 0 ]; then
    echo "smoke test PASSED - $PASS assertions"
    exit 0
fi
echo "smoke test FAILED - $FAIL of $((PASS + FAIL)) assertions" >&2
exit 1
