#!/usr/bin/env bash
# Boot STAR OS under machines that are not the development machine.
#
# `smoke-test.sh` answers "does it work". This answers "does it work on
# something else", which is a different question and the one a kernel gets wrong.
# Every branch below is code that never executes on the default QEMU machine:
#
#   * a CPU without PDPE1GB takes the 2 MiB fallback in the page-table walk -
#     512 times as many entries, and an entirely separate path through the
#     mapper that the 1 GiB machine never touches;
#   * a CPU without SMEP/SMAP takes the "unsupported" branch in `vm::init` and
#     skips the SMAP self-test, which is the branch a 2012 laptop takes;
#   * 128 MiB of RAM makes the heap a visible fraction of the machine and the
#     pool small enough that the buddy allocator's power-of-two rounding throws
#     away real memory;
#   * 4 GiB moves the top of RAM past the linear map's 4 GiB floor, so the map
#     is sized by the machine rather than by the constant;
#   * no VGA means the firmware reports no GOP at all and the whole framebuffer
#     path is absent - the case a headless server presents, and the one where a
#     console that assumed a screen would fault;
#   * four cores means three of them are parked by firmware while the boot core
#     rewrites CR3 and CR4 underneath them;
#   * the release profile is a different compiler output entirely: LTO, opt-level
#     "z", and no debug symbols, over naked functions, inline assembly and a
#     linker script. Nothing about the debug build predicts it.
#
# Each case names what it expects to be *different*, not just that it booted.
# A case that only checked for "phase 2.1 complete" would pass with the fallback
# path silently never taken.
set -euo pipefail

cd "$(dirname "$0")/.."

TIMEOUT="${TIMEOUT:-45}"

# A fixed directory, emptied at the start and *kept* afterwards. A matrix that
# deletes its logs on the way out can tell you that twelve assertions failed and
# nothing whatsoever about why — and the first thing that goes wrong is usually
# not an assertion at all but QEMU refusing to start, which leaves every case
# failing identically and the evidence in a temporary directory that no longer
# exists.
LOG_DIR="target/boot-matrix"
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

PASS=0
FAIL=0
CASE=""
# Failures within the current case, so a case that goes wrong can show its log
# once rather than every assertion showing it.
CASE_FAILED=0

expect() {
    local log="$1" what="$2" pattern="$3"
    if grep -qE -- "$pattern" "$log"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        CASE_FAILED=$((CASE_FAILED + 1))
        echo "  [$CASE] MISSING: $what" >&2
        echo "           expected /$pattern/" >&2
    fi
}

forbid() {
    local log="$1" what="$2" pattern="$3"
    if grep -qE -- "$pattern" "$log"; then
        FAIL=$((FAIL + 1))
        CASE_FAILED=$((CASE_FAILED + 1))
        echo "  [$CASE] PRESENT BUT FORBIDDEN: $what" >&2
        grep -nE -- "$pattern" "$log" | head -3 >&2
    else
        PASS=$((PASS + 1))
    fi
}

# Announce a case and reset its failure count.
begin() {
    CASE="$1"
    CASE_FAILED=0
    echo "==> [$CASE]"
}

# Show what the machine actually said, if this case went wrong. Without it the
# report says which patterns did not match and leaves the reader to guess
# whether the kernel misbehaved or QEMU never started.
end() {
    local log="$1"
    [ "$CASE_FAILED" -eq 0 ] && return 0
    echo "  --- last of $log ---" >&2
    if [ -s "$log" ]; then
        tail -20 "$log" | sed 's/^/  | /' >&2
    else
        echo "  | (empty: QEMU produced no output at all)" >&2
    fi
    echo "  ---" >&2
}

# Boot with extra QEMU arguments appended. Later options win for `-cpu` and
# `-vga`, which is what lets a case override what run-qemu.sh chose.
#
# stdin comes from /dev/null: `run-qemu.sh` passes `-serial stdio`, so QEMU takes
# the terminal and puts it in raw mode. That is what is wanted when a person runs
# it, and exactly wrong here — seven of them in a row, fighting over the same
# terminal with whatever else is attached to it.
boot() {
    local log="$1"
    shift
    timeout "$TIMEOUT" ./scripts/run-qemu.sh --headless -- "$@" > "$log" 2>&1 < /dev/null || true
}

# Every case must get through the whole boot, whatever else it does differently.
reached_the_end() {
    local log="$1"
    expect "$log" "the kernel was entered"     'STAR OS microkernel \(x86_64\)'
    expect "$log" "own tables loaded"          'vm: cr3 0x[0-9a-f]+'
    expect "$log" "the frame pool converged"   'frames: [0-9]+ rounds of up to [0-9]+ allocations converged'
    expect "$log" "timer interrupts arrived"   'irq: [0-9]+ timer interrupts delivered on vector 32'
    # And again through the APICs, on a route read out of the MADT rather than
    # assumed. The GSI is not asserted here - it is a property of the machine, and
    # the machines below differ.
    expect "$log" "the MADT was read"          'acpi: madt at 0x[0-9a-f]+'
    expect "$log" "the local APIC came up"     'lapic: id [0-9]+, .*enabled'
    expect "$log" "the APIC route was taken"   'irq: [0-9]+ timer interrupts delivered on vector 48 through the I/O APIC'
    # The clock, measured against the HPET rather than assumed. The APIC timer's
    # rate is a property of the machine, so it is not asserted - what is asserted
    # is that a hundred ticks at a hundred hertz take a second, whatever that rate
    # turns out to be.
    expect "$log" "the HPET decoded"           'hpet: [0-9]+ Hz \([0-9]+ fs per tick\)'
    expect "$log" "the APIC timer was calibrated" 'lapic timer: [0-9]+ ticks/s at divisor 16'
    expect "$log" "a second measured as a second" \
        'timer: 100 interrupts at 100 Hz took (0\.9[89][0-9]|1\.0[01][0-9]) s by the HPET'
    # And two tasks sharing that clock's ticks. The step counts are properties of
    # the machine's speed and are not asserted; what is asserted is that both
    # tasks finished, that the timer forced the switches, that each saw the other
    # advance while it was running, and that both stacks came back.
    expect "$log" "both tasks finished under preemption" \
        'sched: [0-9]+ switches \([1-9][0-9]* forced by the timer\), 2 of 2 tasks finished'
    expect "$log" "the tasks interleaved" \
        'saw B move [1-9][0-9]* times; B took [0-9]+ steps and saw A move [1-9][0-9]* times'
    expect "$log" "dead stacks were reclaimed" \
        'sched: 2 dead stacks reaped, 64 KiB returned to the heap'
    # And ring 3. The step and tick counts are properties of the machine; what is
    # asserted is that user code ran, that the timer interrupted it *there*
    # (which needs TSS.rsp0 and nothing else can supply it), and that a forced
    # non-canonical return faulted in ring 3 rather than in the kernel.
    expect "$log" "a real ELF was loaded"      'user: image [0-9]+ bytes, entry 0x400000, 2 loadable segment\(s\)'
    expect "$log" "two spaces, not one"        'user: two spaces, cr3 0x[0-9a-f]+ and 0x[0-9a-f]+'
    expect "$log" "ring 3 ran"                 'user 1: running at 0x400000 in its own address space'
    expect "$log" "a fault killed only its own task" 'user 1: still running after its neighbour faulted'
    expect "$log" "the dead trees came back"   'user: 2 address space\(s\) torn down, [0-9]+ frames returned; ([0-9]+) -> \1 frames still out'
    expect "$log" "ring 3 was preemptible"     'user: [1-9][0-9]* timer interrupts arrived from ring 3'
    expect "$log" "a bad sysret faulted in ring 3" \
        'user fault: task "N" took vector 13 - #GP general protection fault in ring 3'
    expect "$log" "and only the task died"     'killing the task; the kernel continues'
    # And phase 3.3. The three that are machine-independent claims rather than
    # counts: messages balanced exactly, a full ring parked a sender on the
    # request endpoint (the `-cpu qemu64` machine is also the one without SMAP,
    # so this is where a `stac` that is `#UD` would surface — the message copy is
    # on the same path), and a revocation reached another task's table.
    expect "$log" "messages balanced"          'ipc: 54 messages sent and 54 received'
    expect "$log" "a full ring parked a sender" \
        'send\(s\) waited for a ring slot \([1-9][0-9]* on the request endpoint'
    expect "$log" "revocation crossed tasks"   '\[client\] the same handle now answers BadHandle'
    expect "$log" "the storm kept its order"   '\[ipc-storm\] sequence sum exact: 408'
    expect "$log" "all six spaces came back"   'ipc: 6 tasks finished, every task.s frames returned \(([0-9]+) -> \1 frames out\)'
    expect "$log" "the boot claimed the phase" 'phase 3.3 complete'
    forbid "$log" "a self-test failed"         'SELF-TEST FAILED|not claiming phase'
    forbid "$log" "the loader gave up"         'BOOT FAILED'
    forbid "$log" "a panic"                    'KERNEL PANIC'
    forbid "$log" "the tree was refused"       'vm: refusing to switch tables'
    # The deliberate double fault at the end of the boot is expected; any other
    # fatal fault is not.
    forbid "$log" "an unexpected fatal fault"  'KERNEL FAULT: vector (0|6|10|11|12|13|14) '
    expect "$log" "the guard page still catches an overflow" \
        'KERNEL FAULT: vector 8 - #DF double fault'
}

echo "==> staging (debug)"
./scripts/mkesp.sh > /dev/null

# ---------------------------------------------------------------------------
begin "cpu without 1 GiB pages"
L="$LOG_DIR/qemu64.log"
boot "$L" -cpu qemu64
reached_the_end "$L"
# The whole point: the mapper's other branch. `qemu64` advertises neither
# PDPE1GB nor SMEP/SMAP, so this is the only place three fallbacks run at once.
expect "$L" "the loader fell back to 2 MiB pages"  'paging: .*\(2 MiB pages\)'
expect "$L" "the kernel fell back too"             'vm: cr3 0x[0-9a-f]+, linear 4 GiB \(2 MiB pages\)'
expect "$L" "SMEP reported as absent, not assumed" 'smep unsupported'
expect "$L" "SMAP reported as absent"              'smap unsupported'
expect "$L" "the SMAP self-test said why it was skipped" \
    'smap: not supported by this CPU, self-test skipped'
forbid "$L" "claimed a protection the CPU lacks"   'smep on|smap on'
end "$L"

# ---------------------------------------------------------------------------
begin "128 MiB of RAM"
L="$LOG_DIR/small.log"
boot "$L" -m 128M
reached_the_end "$L"
# 0x8000000 is 128 MiB exactly: the extent comes from the machine, not from a
# constant. (The "described" figure is larger because it counts the device
# apertures, which is what the line after it says.)
# The trailing class rather than `$`: both consoles emit CRLF, so every line in
# these logs ends with a carriage return and an anchored match never fires.
expect "$L" "RAM extent read from the machine" 'RAM tops out at 0x8000000[^0-9a-f]'
# The heap is carved before the pool and sized from the run, so on a small
# machine it is a visible fraction of it. It must still fit.
expect "$L" "heap and pool both fit"  'memory: heap [0-9]+ KiB at 0x[0-9a-f]+, pool [0-9]+ MiB'
# The linear map has a 4 GiB floor precisely so the framebuffer, which lives
# above RAM, stays reachable on a machine this small.
expect "$L" "the linear map still reaches the framebuffer" 'linear 4 GiB'
end "$L"

# ---------------------------------------------------------------------------
begin "4 GiB of RAM"
L="$LOG_DIR/big.log"
boot "$L" -m 4G
reached_the_end "$L"
# 0x180000000 is 6 GiB, not 4: QEMU splits a 4 GiB guest around the PCI hole,
# putting roughly half the RAM below 2 GiB and the rest at 4 GiB upwards. So the
# extent of RAM is not the amount of RAM, and a kernel that assumed otherwise
# would lose everything above the hole.
expect "$L" "RAM extends past the 4 GiB floor" 'RAM tops out at 0x180000000[^0-9a-f]'
# Sized by the machine now, not by MIN_LINEAR. If this ever reads 4 GiB again,
# the map is being sized by the constant and a machine with more RAM than that
# has memory the kernel cannot address.
expect "$L" "the linear map grew past its floor" 'linear [5-9] GiB|linear [1-9][0-9]+ GiB'
forbid "$L" "the aperture stretched it"          'linear [0-9]{3,} GiB'
expect "$L" "the pool grew with the machine"     'pool [0-9]{4,} MiB'
# This machine is the one that used to make the loss visible, so it is the one
# that now has to prove the loss is gone. A 4 GiB guest reports about 4041 MiB
# usable, splits it either side of the PCI hole, and the exclusions cut two more
# holes in whichever half the kernel landed in. Taking only the largest run and
# rounding it down to a power of two managed 1024 MiB of that - a quarter of the
# machine, asserted rather than fixed.
#
# Now every run goes in and each is decomposed into powers of two, so the pool is
# within a heap's worth of all the usable memory there is.
expect "$L" "the pool covers essentially all usable RAM" 'pool 40[0-9]{2} MiB over '
forbid "$L" "usable RAM left unmanaged"          'is not under management'
expect "$L" "the runs on both sides of the hole are in" \
    'pool [0-9]+ MiB over ([2-9]|[0-9]{2,}) run\(s\)'
# The metadata bill this buys: 8 bytes per frame over four times as many frames.
# Asserted as a bound so a future change to the decomposition cannot quietly make
# it ten times rather than four.
expect "$L" "the heap grew to pay for it, but only so far" 'heap [0-9]{4} KiB at 0x'
end "$L"

# ---------------------------------------------------------------------------
begin "no display"
L="$LOG_DIR/novga.log"
boot "$L" -vga none
reached_the_end "$L"
# A headless server. The firmware reports no GOP, so the console is serial only
# and every framebuffer path is skipped rather than fed a null.
expect "$L" "the loader said so rather than carrying on" \
    'gop: no graphics output protocol - serial only'
expect "$L" "the kernel was told there is none" 'framebuffer: none reported by firmware'
forbid "$L" "the screen was attached anyway" 'console: mirroring to the screen'
forbid "$L" "the console tried and failed"   'console: screen unusable'
end "$L"

# ---------------------------------------------------------------------------
begin "four cores"
L="$LOG_DIR/smp.log"
boot "$L" -smp 4
reached_the_end "$L"
# Nothing starts the other three, so this is really a test that firmware parking
# them does not disturb the boot core rewriting CR3 and CR4.
forbid "$L" "output from a second core interleaved" 'STAR OS microkernel.*STAR OS microkernel'
end "$L"

# ---------------------------------------------------------------------------
begin "i440fx chipset"
L="$LOG_DIR/i440fx.log"
boot "$L" -machine pc
reached_the_end "$L"
# A different chipset means a different memory map, a different PCI hole and a
# different set of reserved ranges - all of it read from firmware rather than
# assumed, which is the claim being tested. The 12 GiB aperture at 1012 GiB is a
# q35 thing and does not appear here, so the filter has to be right in both
# directions: it must not drop real memory on a machine that has no aperture.
forbid "$L" "the linear map stretched"      'linear [0-9]{3,} GiB'
expect "$L" "RAM was found and mapped"      'RAM tops out at 0x[0-9a-f]+'
expect "$L" "a pool was built"              'pool [0-9]+ MiB'
end "$L"

# ---------------------------------------------------------------------------
begin "release profile"
./scripts/mkesp.sh --release > /dev/null
L="$LOG_DIR/release.log"
boot "$L"
reached_the_end "$L"
# LTO and opt-level "z" over naked functions, inline assembly, a linker script
# and a page-table walk. The self-tests are the same; what is being tested is
# that the optimiser did not reason its way through any of them.
expect "$L" "a null dereference still faults" 'trap: #PF at 0x0'
expect "$L" "SMAP still refuses the write"    'smap: the write faulted and did not happen'
expect "$L" "int3 still returns"              'trap: #BP at RIP=0x[0-9a-f]+, resuming'
end "$L"
./scripts/mkesp.sh > /dev/null

echo
if [ "$FAIL" -eq 0 ]; then
    echo "boot matrix PASSED - $PASS assertions across 7 machines"
    echo "logs in $LOG_DIR"
    exit 0
fi
echo "boot matrix FAILED - $FAIL of $((PASS + FAIL)) assertions" >&2
echo "full logs in $LOG_DIR" >&2
exit 1
