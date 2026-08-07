#!/usr/bin/env bash
# Stage an EFI System Partition layout for STAR OS.
#
# Builds both halves — the loader (PE/COFF, for firmware) and the kernel (ELF,
# for hardware) — and places them where the firmware and the loader respectively
# expect to find them:
#
#   EFI/BOOT/BOOTX64.EFI   the removable-media boot path every UEFI firmware
#                          tries without needing an NVRAM boot entry
#   staros/kernel          where crates/boot-uefi/src/fs.rs opens it
#   staros/initramfs       optional
#
# By default it stages into a directory, which is all QEMU needs
# (`-drive format=raw,file=fat:rw:<dir>`). With --to <mounted-esp> it copies onto
# a real, already-mounted EFI partition — the same shape as the aarch64 tree's
# pi5-sdcard.sh, and for the same reason: mounting is the one step worth leaving
# to the person who knows which disk is theirs.
set -euo pipefail

cd "$(dirname "$0")/.."

STAGE="target/esp"
TARGET_ESP=""
PROFILE="debug"
INITRAMFS=""

usage() {
    cat <<'EOF'
usage: mkesp.sh [--to <mounted-esp>] [--release] [--initramfs <file>]

  --to <dir>          copy onto a mounted EFI System Partition instead of
                      staging under target/esp
  --release           build with --release (smaller, optimised)
  --initramfs <file>  include an initramfs; without it the kernel boots with none
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --to) TARGET_ESP="${2:?--to needs a path}"; shift 2 ;;
        --release) PROFILE="release"; shift ;;
        --initramfs) INITRAMFS="${2:?--initramfs needs a path}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "mkesp.sh: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

RELEASE_FLAG=""
[ "$PROFILE" = "release" ] && RELEASE_FLAG="--release"

echo "==> building the loader (x86_64-unknown-uefi)"
# shellcheck disable=SC2086  # deliberate word splitting of the optional flag
cargo kloader $RELEASE_FLAG
echo "==> building the kernel (x86_64-unknown-none)"
# shellcheck disable=SC2086
cargo kbuild $RELEASE_FLAG

LOADER="target/x86_64-unknown-uefi/$PROFILE/staros-boot-uefi.efi"
KERNEL="target/x86_64-unknown-none/$PROFILE/kernel"

for f in "$LOADER" "$KERNEL"; do
    [ -f "$f" ] || { echo "mkesp.sh: expected build output missing: $f" >&2; exit 1; }
done

# Check the two things that make the pair bootable, before writing anything.
# Both failures are otherwise diagnosed by a blank screen.
#
#   1. The loader must be a PE32+ EFI application. A plain ELF here means the
#      --target flag was lost and firmware will not touch the file.
#   2. The kernel must be ET_EXEC, not ET_DYN. A PIE image is rejected by the
#      loader's ELF parser, which is the good outcome — but finding out here is
#      faster than finding out at boot.
if ! head -c 2 "$LOADER" | grep -q '^MZ'; then
    echo "mkesp.sh: $LOADER is not a PE image - was it built for x86_64-unknown-uefi?" >&2
    exit 1
fi
if ! readelf -h "$KERNEL" | grep -q 'Type:[[:space:]]*EXEC'; then
    echo "mkesp.sh: $KERNEL is not ET_EXEC - check relocation-model in .cargo/config.toml" >&2
    readelf -h "$KERNEL" | grep 'Type:' >&2
    exit 1
fi

if [ -n "$TARGET_ESP" ]; then
    [ -d "$TARGET_ESP" ] || { echo "mkesp.sh: '$TARGET_ESP' is not a directory" >&2; exit 1; }
    if ! mountpoint -q "$TARGET_ESP" 2>/dev/null; then
        # Refuse a plain directory: writing an ESP layout into someone's home
        # directory succeeds silently and boots nothing.
        echo "mkesp.sh: '$TARGET_ESP' is not a mount point - mount the EFI partition there first" >&2
        exit 1
    fi
    DEST="$TARGET_ESP"
else
    DEST="$STAGE"
    rm -rf "$DEST"
fi

mkdir -p "$DEST/EFI/BOOT" "$DEST/staros"
install -m 0644 "$LOADER" "$DEST/EFI/BOOT/BOOTX64.EFI"
install -m 0644 "$KERNEL" "$DEST/staros/kernel"
if [ -n "$INITRAMFS" ]; then
    [ -f "$INITRAMFS" ] || { echo "mkesp.sh: no such initramfs: $INITRAMFS" >&2; exit 1; }
    install -m 0644 "$INITRAMFS" "$DEST/staros/initramfs"
else
    rm -f "$DEST/staros/initramfs"
fi
sync 2>/dev/null || true

echo
echo "staged $PROFILE build in $DEST"
printf '  %-28s %8s bytes\n' "EFI/BOOT/BOOTX64.EFI" "$(stat -c%s "$DEST/EFI/BOOT/BOOTX64.EFI")"
printf '  %-28s %8s bytes\n' "staros/kernel" "$(stat -c%s "$DEST/staros/kernel")"
[ -n "$INITRAMFS" ] && printf '  %-28s %8s bytes\n' "staros/initramfs" "$(stat -c%s "$DEST/staros/initramfs")"
echo
if [ -z "$TARGET_ESP" ]; then
    echo "boot it with: ./scripts/run-qemu.sh"
fi
