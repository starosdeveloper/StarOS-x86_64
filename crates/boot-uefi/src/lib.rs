//! STAR OS UEFI loader — everything except the entry point.
//!
//! The binary is built for `x86_64-unknown-uefi` and cannot be run under
//! `cargo test`. But most of what a loader gets wrong is not firmware
//! interaction, it is **interpretation**: descriptor strides, memory-type
//! meanings, address arithmetic near the end of the address space. So the work
//! lives in this library, which also compiles for the host, and `src/main.rs`
//! holds only `efi_main` and the panic handler.
//!
//! That split is what lets [`memmap`]'s tests check the `#[repr(C)]` offsets in
//! [`efi`] against the offsets the conversion actually reads — on the host,
//! before any of it runs on a machine whose only diagnostic is a blank screen.
//!
//! What the loader does, in order, is in `boot::run`; `docs/SPEC.md` §2.2 is the
//! same list in prose, and the two are meant to be read side by side.

#![cfg_attr(not(test), no_std)]

pub mod alloc;
pub mod boot;
pub mod console;
pub mod efi;
pub mod fs;
pub mod memmap;
pub mod paging;
