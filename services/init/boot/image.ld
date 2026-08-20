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
        /* Landing-pad tables `core` emits alongside its panic paths. Named
         * explicitly since phase 3.3, when the program grew Rust code and
         * therefore its first `core` instantiation: an output section this
         * script does not place gets one of lld's own, at whatever address it
         * likes, and the result is a third PT_LOAD whose p_vaddr is not page
         * aligned — which the kernel's loader rightly refuses. Read-only data as
         * far as the loader is concerned, so it belongs here; nothing reads it at
         * run time, because the program is built `-Cpanic=abort`. */
        *(.gcc_except_table .gcc_except_table.*)
    }

    /* Page-align onto a fresh frame so the loader maps the writable segment with
     * different rights than the read-execute text. */
    . = ALIGN(0x1000);

    .data : {
        *(.data .data.*)
        /* Placed, not discarded, since phase 3.3. LLVM reaches the memory
         * intrinsics the Rust roles need — `memcpy`, `memset` — through the
         * global offset table even at `-Crelocation-model=static`, because a
         * `#[no_mangle]` symbol is one another object could in principle
         * interpose. Discarding the table left those `call [rip+…]` instructions
         * pointing at address 8, which is a page fault in ring 3 the first time a
         * program formats a line. For a static ET_EXEC the linker fills each
         * entry with the symbol's absolute address, so the indirection costs one
         * load and nothing else. */
        *(.got .got.plt)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
