/* Link layout for the ring-3 boot image (services/init/boot/image.rs).
 *
 * The kernel's ELF loader maps this program from USER_BASE = 0x400000, honouring
 * each PT_LOAD segment's own R/W/X rights (see `crates/kernel/src/addrspace.rs`).
 * It is linked there and uses absolute virtual addresses; `_start` is forced
 * first so `e_entry` lands on its first instruction.
 *
 * 0x400000 is not an arbitrary choice: it is the address a linker gives a
 * non-PIE x86-64 executable by default, so a program built by any ordinary
 * toolchain lands where this one does without the kernel learning a new number.
 *
 * Two loadable segments on purpose, so the loader is exercised on real, differing
 * permissions:
 *   - read + execute (.text and .rodata);
 *   - read/write (.data and .bss), page-aligned onto its own frame.
 * `-z max-page-size=4096` (set by build.rs) keeps that alignment at 4 KiB rather
 * than lld's default 2 MiB, which would otherwise pad the file with megabytes of
 * zeroes that `include_bytes!` would bake into the kernel.
 *
 * .bss is deliberately non-empty: it makes p_memsz exceed p_filesz, which is the
 * only thing that exercises the loader's zero-filled tail. A program whose
 * segments are all file-backed cannot tell a loader that zeroes the tail from one
 * that leaves whatever the frame last held.
 *
 * The per-process id byte and the tick counter are *not* part of this image. They
 * are kernel-seeded pages placed sixteen gigabytes above it, which is what proves
 * the address space is genuinely sparse rather than one contiguous block.
 */

ENTRY(_start)

USER_BASE = 0x400000;

SECTIONS
{
    . = USER_BASE;

    .text : {
        KEEP(*(.text.start))   /* _start must be first (== e_entry) */
        *(.text .text.*)
        *(.rodata .rodata.*)
    }

    /* Page-align onto a fresh frame so the loader maps the writable segment with
     * different rights than the read-execute text. */
    . = ALIGN(0x1000);

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.got*)
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
