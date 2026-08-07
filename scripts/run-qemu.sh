#!/usr/bin/env bash
# Boot STAR OS under QEMU with OVMF — real UEFI firmware, not a shortcut.
#
# There is no `-kernel` here on purpose. QEMU's `-kernel` would skip the loader
# entirely and hand the kernel a hand-off it never agreed to; the whole point of
# phase 1.1 is that firmware loads BOOTX64.EFI, which loads the kernel. What runs
# under QEMU is therefore the same sequence that runs on the machine on the desk.
#
# The ESP is a *directory*, via QEMU's virtual FAT (`fat:rw:`), so a rebuild is
# a rebuild and not an image-writing ritual.
set -euo pipefail

cd "$(dirname "$0")/.."

ESP="target/esp"
MEMORY="512M"
CPUS="1"
EXTRA=()
DEBUG=0
HEADLESS=0
SHOT=""
SHOT_DELAY="${SHOT_DELAY:-12}"
MON=""


usage() {
    cat <<'EOF'
usage: run-qemu.sh [--memory 512M] [--cpus N] [--debug] [-- <extra qemu args>]

  --memory SIZE   guest RAM (default 512M)
  --cpus N        SMP cores (default 1; the kernel is single-core until phase 2)
  --debug         start stopped with a gdb stub on :1234, and log interrupts
                  attach with:  gdb target/x86_64-unknown-none/debug/kernel
                                (gdb) target remote :1234
  --screenshot F  after ${SHOT_DELAY}s (SHOT_DELAY=n to change), dump the emulated
                  display to F as a PPM through the QEMU monitor, and imply
                  --headless. The only way to check that anything was actually
                  *drawn* — a serial log cannot tell a blank screen from a full
                  one.
  --headless      no QEMU window; serial only. The framebuffer still exists —
                  firmware sets up the emulated VGA either way — so GOP is
                  reported to the loader exactly as it would be with a display.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --memory) MEMORY="${2:?--memory needs a size}"; shift 2 ;;
        --cpus) CPUS="${2:?--cpus needs a number}"; shift 2 ;;
        --debug) DEBUG=1; shift ;;
        --headless) HEADLESS=1; shift ;;
        --screenshot) SHOT="${2:?--screenshot needs a path}"; HEADLESS=1; shift 2 ;;
        --) shift; EXTRA=("$@"); break ;;
        -h|--help) usage; exit 0 ;;
        *) echo "run-qemu.sh: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

command -v qemu-system-x86_64 >/dev/null 2>&1 || {
    echo "run-qemu.sh: qemu-system-x86_64 not found" >&2
    echo "  Arch:   sudo pacman -S qemu-system-x86" >&2
    echo "  Debian: sudo apt install qemu-system-x86" >&2
    exit 1
}

# OVMF lives in a different place on every distribution, and the split
# CODE/VARS pair matters: CODE is read-only firmware, VARS is the NVRAM this
# script copies so a boot cannot dirty the system file.
CODE=""
VARS=""
for pair in \
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.fd:/usr/share/edk2/x64/OVMF_VARS.fd" \
    "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd:/usr/share/edk2-ovmf/x64/OVMF_VARS.fd" \
    "/usr/share/qemu/edk2-x86_64-code.fd:/usr/share/qemu/edk2-i386-vars.fd"
do
    c="${pair%%:*}"; v="${pair##*:}"
    if [ -f "$c" ] && [ -f "$v" ]; then CODE="$c"; VARS="$v"; break; fi
done
[ -n "$CODE" ] || {
    echo "run-qemu.sh: no OVMF firmware found" >&2
    echo "  Arch:   sudo pacman -S edk2-ovmf" >&2
    echo "  Debian: sudo apt install ovmf" >&2
    exit 1
}

[ -f "$ESP/EFI/BOOT/BOOTX64.EFI" ] || {
    echo "run-qemu.sh: no staged ESP at $ESP - run ./scripts/mkesp.sh first" >&2
    exit 1
}

# A private, writable copy of the variable store. Without it QEMU either refuses
# to start or writes boot entries into the distribution's file.
RUNVARS="target/OVMF_VARS.fd"
[ -f "$RUNVARS" ] || cp "$VARS" "$RUNVARS"
chmod u+w "$RUNVARS"

ARGS=(
    -machine q35
    # `max`, not the `qemu64` default: that model does not advertise PDPE1GB, so
    # the loader falls back to 2 MiB pages and builds 512x the page tables for
    # the same mapping. Real hardware has 1 GiB pages; the emulator should not
    # be the only place the other branch is ever exercised.
    -cpu max
    -smp "$CPUS"
    -m "$MEMORY"
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$CODE"
    -drive "if=pflash,format=raw,unit=1,file=$RUNVARS"
    -drive "format=raw,file=fat:rw:$ESP"
    # Serial to stdout: the loader and the kernel both write here, and their
    # lines interleave in the order they happened, which is the evidence.
    -serial stdio
    # No reboot on triple fault, and log the fault. Without this a mistake in the
    # page tables presents as an endless reboot loop with nothing on screen; with
    # it, QEMU prints the CPU state at the moment it gave up.
    -no-reboot
    -d guest_errors
)
[ "$HEADLESS" = "1" ] && ARGS+=(-display none)
if [ -n "$SHOT" ]; then
    MON="$(mktemp -u -t staros-mon.XXXXXX)"
    ARGS+=(-monitor "unix:$MON,server,nowait")
    # Detached, because QEMU never returns on its own: the kernel halts. The
    # delay has to outlast firmware plus boot, and 12s is generous for TCG.
    (
        sleep "$SHOT_DELAY"
        python3 - "$MON" "$(readlink -f "$SHOT")" <<'PYEOF'
import socket, sys, time
sock, out = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(50):
    try:
        s.connect(sock)
        break
    except OSError:
        time.sleep(0.2)
else:
    sys.exit("screenshot: could not reach the QEMU monitor")
s.settimeout(5)
try:
    s.recv(4096)              # the monitor banner
except OSError:
    pass
s.sendall(f"screendump {out}\n".encode())
time.sleep(1.5)               # let the dump finish before the socket closes
s.close()
PYEOF
        rm -f "$MON"
    ) &
fi
# `-d int` traces every interrupt and exception. Far too loud for a normal run,
# and exactly what is wanted when the question is "which fault killed it".
[ "$DEBUG" = "1" ] && ARGS+=(-s -S -d guest_errors,int)

echo "==> firmware: $CODE"
echo "==> esp:      $ESP"
[ "$DEBUG" = "1" ] && echo "==> stopped, gdb stub on :1234"
echo
exec qemu-system-x86_64 "${ARGS[@]}" "${EXTRA[@]}"
