/* Kernel layout for x86_64.
 *
 * The kernel is linked into the TOP 2 GiB of the 64-bit address space
 * (0xFFFFFFFF80000000), the "kernel" code model's window. Two consequences, both
 * deliberate:
 *
 *  - Every symbol is reachable by a RIP-relative access with a 32-bit
 *    displacement, so the image needs no GOT, no PLT and no relocation
 *    processing at boot. The loader copies it and jumps.
 *  - The kernel's addresses are permanently distinct from user addresses, which
 *    live in the bottom half. This is the same split TTBR0/TTBR1 gives for free
 *    on aarch64 — x86_64 has one page-table root, so the separation is by
 *    address range plus the U/S bit in each entry, and never by luck.
 *
 * The load address (LMA) is left to the loader: it places the image in whatever
 * physical memory the firmware reported free, then maps it here. Sections are
 * 4 KiB aligned so each can be mapped with its own rights — W^X is enforced by
 * the mapping, and that requires the boundaries to be page boundaries.
 */

ENTRY(_start)

KERNEL_VMA = 0xFFFFFFFF80000000;

PHDRS
{
    text   PT_LOAD FLAGS(5);  /* R-X */
    rodata PT_LOAD FLAGS(4);  /* R-- */
    data   PT_LOAD FLAGS(6);  /* RW- */
    stack  PT_LOAD FLAGS(6);  /* RW- , separated from .data by the guard page */
}

SECTIONS
{
    . = KERNEL_VMA;
    __kernel_start = .;

    .text : ALIGN(4K) {
        *(.text.start)      /* the entry point first, so its address is known */
        *(.text .text.*)
    } :text

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    } :rodata

    .data : ALIGN(4K) {
        *(.data .data.*)
        *(.got .got.plt)    /* should be empty under the kernel code model */
    } :data

    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4K);
        __bss_end = .;
    } :data

    /* The boot stack costs nothing in the image (NOLOAD) and is preceded by a
     * guard page that is genuinely unmapped — a kernel stack overflow must fault
     * rather than quietly overwrite .bss, which is the failure mode that produces
     * impossible bug reports.
     *
     * The guard is real because of how it is placed: the location counter is
     * advanced across it *outside* any output section, so no PT_LOAD covers those
     * 4 KiB and the loader, which maps segment by segment, has nothing to map
     * there. That is also why .stack needs its own program header — sharing
     * :data would stretch that segment across the gap and map it after all. */
    . = ALIGN(4K);
    __stack_guard = .;
    . += 4K;

    .stack (NOLOAD) : ALIGN(4K) {
        __stack_bottom = .;
        . += 64K;
        __stack_top = .;
    } :stack

    . = ALIGN(4K);
    __kernel_end = .;
    __kernel_size = __kernel_end - __kernel_start;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
    }
}
