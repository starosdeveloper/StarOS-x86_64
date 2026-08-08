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

# A fixed directory, emptied at the start and kept afterwards. Deleting the logs
# on the way out means a failure report can say which patterns did not match and
# nothing about why — and when the cause is QEMU refusing to start rather than
# the kernel misbehaving, every assertion fails identically and the one line that
# explains it has already been thrown away.
LOG_DIR="target/smoke-test"
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

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
    #
    # stdin from /dev/null: `-serial stdio` makes QEMU take the terminal and put
    # it in raw mode, which is right when a person runs it by hand and wrong for
    # four boots in a row sharing a terminal with whatever else is attached.
    timeout "$TIMEOUT" ./scripts/run-qemu.sh --headless "$@" > "$log" 2>&1 < /dev/null || true
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

# --- phase 1.3: the CPU tables -------------------------------------------
# Everything below is evidence that a fault is a report rather than a reset.
# There is no other kind of evidence available: an IDT that is subtly wrong and
# one that is right are both silent until something faults.
expect "$L" "GDT loaded with the SYSCALL layout" 'gdt: loaded, kernel cs 0x08 ss 0x10, tss 0x30'
expect "$L" "IDT loaded with all 256 vectors" 'idt: 256 vectors'
# A vector with no error code, returning through iretq.
expect "$L" "int3 was caught and resumed"    'trap: #BP at RIP=0x[0-9a-f]+, resuming'
# A vector *with* an error code, resumed by rewriting RIP in the saved frame.
# Address 0x0 is still identity-mapped by the loader until phase 1.4, so the
# unmapped address used here is the stack guard page - which also proves the
# guard is genuinely absent from the page tables.
expect "$L" "page fault caught, decoded and resumed" \
    'trap: #PF at 0xffffffff[0-9a-f]+, RIP=0x[0-9a-f]+, err=0x0 \(read from an unmapped page\), resuming at 0x'
expect "$L" "both recoverable traps returned" 'both traps returned to their caller'

# --- phase 1.4: the kernel's own memory ------------------------------------
expect "$L" "memory map summarised"          'memory: [0-9]+ MiB described, [0-9]+ MiB usable, RAM tops out at 0x'
expect "$L" "the map itself is printed"      '^  0x[0-9a-f]+\.\.0x[0-9a-f]+ +[0-9]+ KiB  usable'
expect "$L" "heap and pool carved"           'memory: heap [0-9]+ KiB at 0x[0-9a-f]+, pool [0-9]+ MiB at 0x[0-9a-f]+ \([0-9]+ frames managed\)'
# The tree is walked before it is loaded, because a bad `mov cr3` is a triple
# fault with nothing printed - there is no fault report to read afterwards.
expect "$L" "the new tree verified before the switch" \
    'vm: verified - text 0x[0-9a-f]+ r-x, rodata r--, data rw-, 0x0 and the guard page absent'
forbid "$L" "the tree failed verification"   'vm: refusing to switch tables'
expect "$L" "own tables live, protections on" 'vm: cr3 0x[0-9a-f]+, linear 4 GiB \(1 GiB pages\), smep on, smap on'
# The same device aperture that stretched the loader's map to 1024 GiB: by the
# time the kernel sees the map, UEFI's MMIO type has been folded into Reserved,
# so the filter has to be redone on this side.
forbid "$L" "linear map stretched by an aperture" 'linear [0-9]{3,} GiB'
# Phase 1.3 could not meet this: the loader identity-maps the low 4 GiB, so a
# null dereference read real memory and returned. It is true only now.
expect "$L" "a null dereference finally faults" \
    'trap: #PF at 0x0, RIP=0x[0-9a-f]+, err=0x0 \(read from an unmapped page\)'
expect "$L" "SMAP refused a supervisor write to a user page" 'smap: the write faulted and did not happen'
expect "$L" "stac still opens the hole"      'smap: stac opened the hole, the same write succeeded'
expect "$L" "the frame pool coalesces"       'frames: [0-9]+ rounds of up to [0-9]+ allocations converged'

# --- phase 2.1: device interrupts land where they should --------------------
# The firmware leaves the 8259s delivering on vectors 0..15, which belong to the
# CPU's own exceptions. The base is reported from the driver's record of where it
# put them, not from the constant it was handed, so the line cannot agree with a
# remap that did not happen.
expect "$L" "the 8259 pair moved off the exception vectors" \
    'pic: 8259 pair remapped to vectors 32\.\.48, masks 0xffff'
forbid "$L" "a line came up unmasked"        'pic: WARNING'
expect "$L" "the PIT was programmed as a rate generator" \
    'pit: channel 0 at [0-9]+ Hz on IRQ 0, expecting vector 32'
# The whole point of 2.1, and the only check that can be made: the 8259's vector
# base is write-only, so where it delivers is a question only a delivered
# interrupt can answer. Without the remap this same tick arrives as vector 0 and
# the boot ends in "KERNEL FAULT: vector 0 - #DE divide error" - a division that
# never happened. More than one tick, because one proves delivery but not
# acknowledgement: a missing EOI leaves the line in service and the second never
# comes.
expect "$L" "timer interrupts delivered on the remapped vector and acknowledged" \
    'irq: [0-9]+ timer interrupts delivered on vector 32 and acknowledged'
expect "$L" "interrupts masked again afterwards" 'irq: interrupts masked again'
forbid "$L" "an interrupt on a line nothing asked for" 'on lines nothing asked for'

# --- phase 2.2: the real controller ----------------------------------------
# Everything the APICs need comes out of ACPI, and the kernel says which table it
# read it from rather than recognising addresses.
expect "$L" "the MADT was found and parsed" \
    'acpi: madt at 0x[0-9a-f]+, [0-9]+ cpu\(s\), local apic at 0xfee00000'
expect "$L" "the I/O APIC was located from the table" 'acpi: io apic at 0x[0-9a-f]+, first gsi [0-9]+'
expect "$L" "the local APIC came up enabled" \
    'lapic: id [0-9]+, version 0x[0-9a-f]+, [0-9]+ lvt entries, spurious vector 255, enabled'
forbid "$L" "the local APIC did not enable"  'NOT ENABLED'
expect "$L" "the I/O APIC reported its own size" \
    'ioapic: id [0-9]+, version 0x[0-9a-f]+, [0-9]+ entries covering gsi'
# The criterion for this phase, and the one thing that cannot be guessed: on this
# machine the timer's IRQ 0 arrives as GSI *2*, because the 8259 cascade line took
# GSI 0 first. Programming entry 0 configures a line nothing is attached to, and
# the symptom is silence - no error, no fault, no ticks.
expect "$L" "the GSI came from the MADT, not from the IRQ number" \
    'ioapic: irq 0 arrives on gsi 2 \(remapped by the MADT'
expect "$L" "the timer was routed to a vector above the 8259 range" \
    'ioapic: gsi 2 -> vector 48 on apic [0-9]+'
expect "$L" "interrupts arrived through the I/O APIC and were acknowledged at the local APIC" \
    'irq: [0-9]+ timer interrupts delivered on vector 48 through the I/O APIC and acknowledged'
forbid "$L" "a redirection entry did not read back" 'entry read back as'
forbid "$L" "the local APIC raised a spurious interrupt" 'spurious from the local APIC'

forbid "$L" "a self-test reported failure"   'SELF-TEST FAILED|did not converge|self-test FAILED'
forbid "$L" "a phase was claimed after a failure" 'not claiming phase'
expect "$L" "boot reached the end of phase 2.2" 'phase 2.2 complete'

# The last act: a deliberate stack overflow. Without a TSS, an IST and a #DF
# gate this is a triple fault and the log simply stops - which is exactly what
# reverting `ist_for(8)` produces, and is why this is asserted rather than
# assumed.
expect "$L" "stack overflow reported, not reset" 'KERNEL FAULT: vector 8 - #DF double fault'
expect "$L" "the guard page was named as the cause" 'that is the kernel stack guard page'
expect "$L" "the fatal path halts"           'halting - this core cannot continue'
# The frame is 22 words in a fixed order. Push one word too many or too few and
# every field shifts: RIP reads as zero, and the iretq at the end of the stub
# returns into nothing. Both halves of that signature are forbidden.
forbid "$L" "trap frame shifted by a word"   'RIP=0x0,'
forbid "$L" "fault while returning from a fault" 'KERNEL FAULT: vector 13'
forbid "$L" "an unexpected fatal fault"      'KERNEL FAULT: vector (0|6|10|11|12|14) '

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
    echo "logs in $LOG_DIR"
    exit 0
fi
echo "smoke test FAILED - $FAIL of $((PASS + FAIL)) assertions" >&2
echo "  --- last of the good boot ---" >&2
if [ -s "$LOG_DIR/good.log" ]; then
    tail -20 "$LOG_DIR/good.log" | sed 's/^/  | /' >&2
else
    echo "  | (empty: QEMU produced no output at all)" >&2
fi
echo "full logs in $LOG_DIR" >&2
exit 1
