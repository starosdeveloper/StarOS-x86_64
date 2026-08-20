//! Build the ring-3 boot image and hand its ELF to the kernel.
//!
//! The user program is a *separately compiled* x86-64 executable, not code baked
//! into the kernel's `.text`. This script compiles
//! `services/init/boot/image.rs` with a plain `rustc` invocation using that
//! program's own linker script — which places it at `USER_BASE` = 0x400000 with
//! separate read-execute and read-write `PT_LOAD` segments — and exports the path
//! to the resulting ELF as `STAROS_USER_IMAGE`. The kernel `include_bytes!`s it
//! and `staros-elf64` parses the program headers at run time.
//!
//! `rustc` directly rather than a nested `cargo`, for the same reason the aarch64
//! tree does it: the program is one dependency-free `no_std` file whose body is a
//! single naked function, so the target's pre-compiled `core` is enough — no
//! `-Zbuild-std`, no nested workspace or lockfile, no fight over the target
//! directory lock.
//!
//! ## Why the host target, for a program that never runs on the host
//! `x86_64-unknown-none` is what the kernel itself is built for, and it would be
//! the obvious choice — except that its `core` is not shipped pre-compiled and
//! building it needs `-Zbuild-std`, which is a **cargo** flag with no `rustc`
//! equivalent. The one target whose `core` is always present is the host's.
//!
//! Nothing of that target reaches the output. The program is `#![no_std]`,
//! `#![no_main]`, and its entire body is `naked_asm!`, so no `core` code is
//! instantiated and no libc symbol is referenced; the linker script pins every
//! address; `-Crelocation-model=static` makes it `ET_EXEC` rather than a PIE;
//! and `-Clinker-flavor=ld.lld` links with the `rust-lld` that ships with the
//! toolchain instead of the host's `cc`, so no system library is consulted. What
//! comes out is an ordinary static x86-64 ELF, which is all the kernel's loader
//! is looking at.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());

    let boot_dir = Path::new(&manifest_dir).join("../../services/init/boot");
    // Canonicalise, so the `rerun-if-changed` paths cargo stats are exactly the
    // ones named here — a `..` component that fails to match would silently drop
    // the dependency and leave a stale image linked in.
    let image_rs = canonical(&boot_dir.join("image.rs"));
    let image_ld = canonical(&boot_dir.join("image.ld"));

    println!("cargo:rerun-if-changed={}", image_rs.display());
    println!("cargo:rerun-if-changed={}", image_ld.display());

    let elf = Path::new(&out_dir).join("user.elf");

    let status = Command::new(&rustc)
        .args(["--edition", "2021"])
        .args(["--target", "x86_64-unknown-linux-gnu"])
        .args(["--crate-name", "staros_user_image"])
        .args(["--crate-type", "bin"])
        .arg("-Copt-level=2")
        .arg("-Cpanic=abort")
        // ET_EXEC at a fixed address, not a PIE: the loader maps each segment at
        // its link address and applies no relocations, so a position-independent
        // image would run with every global pointing at zero.
        .arg("-Crelocation-model=static")
        // Symbols and section headers are bytes `include_bytes!` would bake into
        // the kernel for nothing: the loader maps `PT_LOAD` segments and never
        // looks at the symbol table.
        .arg("-Cstrip=symbols")
        .arg("-Clinker=rust-lld")
        .arg("-Clinker-flavor=ld.lld")
        .arg(format!("-Clink-arg=-T{}", image_ld.display()))
        // Two tokens, not the glued `-zmax-page-size=…` form, which lld does not
        // parse. Without it lld assumes 2 MiB pages and pads the file with two
        // megabytes of zeroes between the read-execute and read-write segments.
        .arg("-Clink-arg=-z")
        .arg("-Clink-arg=max-page-size=4096")
        // No RELRO. rustc passes `-z relro -z now` by default, which makes lld
        // cut a separate segment at the end of the read/write data so a dynamic
        // loader can re-protect it — and the cut lands mid-page, producing a
        // third `PT_LOAD` whose `p_vaddr` is not page aligned. This kernel's
        // loader refuses that, correctly: a segment it cannot place on a frame
        // boundary is one it cannot give its own rights. Nothing here is
        // dynamically linked, so there is no relocation table to protect.
        .arg("-Clink-arg=-z")
        .arg("-Clink-arg=norelro")
        .arg("-o")
        .arg(&elf)
        .arg(&image_rs)
        .status()
        .expect("failed to spawn rustc for the ring-3 image");
    assert!(status.success(), "rustc failed to build the ring-3 image");

    // Fail loudly if the image is unexpectedly large. It is a few hundred bytes
    // of code and one page-aligned data segment; anything past this bound means
    // the layout regressed — most likely the max-page-size flag stopping taking
    // effect and the file filling with inter-segment padding.
    const MAX_IMAGE_BYTES: u64 = 32 * 1024;
    let size = std::fs::metadata(&elf)
        .expect("the ring-3 image was not produced")
        .len();
    assert!(
        size <= MAX_IMAGE_BYTES,
        "the ring-3 image is {size} bytes (> {MAX_IMAGE_BYTES}); the segment layout \
         regressed — check the `-z max-page-size=4096` linker flag",
    );

    println!("cargo:rustc-env=STAROS_USER_IMAGE={}", elf.display());
}

/// Canonicalise a path, failing with a clear message if it does not exist, so a
/// mislaid source fails the build immediately rather than silently dropping a
/// `rerun-if-changed` dependency.
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .unwrap_or_else(|e| panic!("ring-3 image source {} not found: {e}", path.display()))
}
