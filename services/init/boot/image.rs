//! The ring-3 boot image — the first user program, as a *separately compiled*
//! x86-64 binary the kernel loads at runtime.
//!
//! Deliberately **not** part of the Cargo workspace build. The kernel's
//! `build.rs` compiles this one file with a plain `rustc` invocation using
//! [`image.ld`](image.ld), which links it at `USER_BASE` = 0x400000 with separate
//! read-execute and read-write `PT_LOAD` segments. The kernel `include_bytes!`s
//! the resulting **ELF** and `staros-elf64` — the same parser the UEFI loader uses
//! on the kernel itself — walks its program headers, so what runs in ring 3 is a
//! real, independently linked executable rather than assembly baked into the
//! kernel's own `.text`.
//!
//! Phase 3.1 could not do that: it had a blob assembled into `.rodata` and copied
//! into a frame, because there was no per-task address space to load anything
//! into. This file is what replaces it.
//!
//! ## What the program does
//! It branches on **its own process id**, a single byte the kernel seeds at
//! `USER_DATA_VA` (0x4_0000_0000) — a different physical page for each task, at
//! the same virtual address. That branch is the demonstration:
//!
//! - **id 1** prints, writes into its own read/write segment, checks that its
//!   `.bss` really arrived zeroed, spins in ring 3 until the kernel's clock has
//!   advanced, prints again to say it outlived its neighbour, and exits cleanly.
//! - **id 2** prints and then dereferences a null pointer, which is a `#PF` in
//!   ring 3. It should die and take nothing else with it.
//!
//! Both are the same image at the same address. The only thing that differs is
//! the page underneath.
//!
//! ## Why it is one naked function
//! No runtime, no relocations, no `core` memory intrinsics — so the pre-compiled
//! `core` for an ordinary target is enough and the build needs no `-Zbuild-std`.
//! Its only inputs are the syscall numbers (which must match
//! `staros_abi::syscall::Syscall`) and the two addresses the kernel seeds.
//!
//! Syscall numbers: `Yield` = 0, `Exit` = 4, `DebugWrite` = 19.

#![no_std]
#![no_main]

use core::arch::naked_asm;
use core::panic::PanicInfo;

/// Entry point. Linked and loaded at 0x400000 and named by `e_entry`, so the
/// kernel's `iretq` lands straight on its first instruction.
///
/// The System V syscall convention: number in `RAX`, arguments in `RDI`, `RSI`,
/// `RDX`, `R10`, `R8`, `R9`, result in `RAX`. `RCX` and `R11` are destroyed by
/// the instruction, which is why `R10` is the fourth argument and why nothing
/// here keeps anything in either across a call.
#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text.start"]
extern "C" fn _start() -> ! {
    naked_asm!(
        // The per-process id, sixteen gigabytes above the image. A different
        // frame per task at the same virtual address — the whole point.
        "mov    r15, 0x400000000",
        "movzx  r14d, byte ptr [r15]",

        // Stamp the id into the message. The message lives in `.data`, so this
        // write only succeeds if the loader mapped the second segment writable —
        // and it is a *private* copy, so the two tasks do not overwrite each
        // other's digit.
        "lea    rdi, [rip + staros_user_msg_running]",
        "lea    eax, [r14 + 48]",           // '0' + id
        "mov    byte ptr [rdi + 5], al",

        // Ids 3 and up are the phase-3.3 roles — server, client, storm senders,
        // storm sink — and they are written in Rust rather than assembly. Four
        // protocols with message buffers, per-sender accumulators and error
        // checking is where hand-written assembly stops being clearer than the
        // thing it is demonstrating. The two 3.2 roles below are untouched: they
        // are the phase's evidence and rewriting them would put a passing test
        // and a new implementation in the same change.
        "cmp    r14d, 3",
        "jb     6f",
        "mov    edi, r14d",
        "call   staros_user_roles",         // never returns
    "6:",

        "cmp    r14d, 1",
        "jne    .Ltask_two",

        // ---- id 1: the task that survives -------------------------------
        "call   .Lputs",

        // `.bss` must have arrived zeroed. p_memsz exceeds p_filesz for the
        // writable segment, and nothing but this checks that the loader zeroed
        // the tail rather than handing over whatever the frame last held.
        "lea    rax, [rip + staros_user_bss_probe]",
        "mov    rax, [rax]",
        "test   rax, rax",
        "jz     2f",
        "lea    rdi, [rip + staros_user_msg_dirty_bss]",
        "call   .Lputs",
        "jmp    .Lexit",
    "2:",

        // Spin in ring 3 until the kernel's clock has moved. Nothing here enters
        // the kernel, so every tick that lands during this loop is an interrupt
        // taken from ring 3 — which needs TSS.rsp0 and a per-task kernel stack.
        "mov    r12, 0x400010000",
        "mov    r13, [r12]",
        "add    r13, 30",
    "3:",
        "mov    rax, [r12]",
        "cmp    rax, r13",
        "jb     3b",

        // Give the CPU up once on purpose, then say we are still here. By now
        // the other task has faulted and been destroyed.
        "xor    eax, eax",                  // Yield
        "syscall",
        "lea    rdi, [rip + staros_user_msg_survived]",
        "call   .Lputs",
        "jmp    .Lexit",

        // ---- id 2: the task that dies -----------------------------------
    ".Ltask_two:",
        "call   .Lputs",
        "lea    rdi, [rip + staros_user_msg_touching_zero]",
        "call   .Lputs",
        // Address zero is not mapped in this space, and this is ring 3. The
        // kernel must report a page fault, destroy this task, and carry on.
        "xor    eax, eax",
        "mov    rax, [rax]",
        // If that returned, address zero was mapped and the isolation this phase
        // claims does not exist. Fault loudly rather than exit quietly.
        "ud2",

    ".Lexit:",
        "mov    eax, 4",                    // Exit
        "syscall",
        "ud2",

        // ---- helper -------------------------------------------------------
        // Write the NUL-terminated string at RDI as one `DebugWrite`. User space
        // measures its own strings; using `call`/`ret` also proves the stack the
        // kernel mapped is writable.
    ".Lputs:",
        "mov    rsi, rdi",
        "xor    ecx, ecx",
    "4:",
        "cmp    byte ptr [rsi + rcx], 0",
        "je     5f",
        "inc    rcx",
        "jmp    4b",
    "5:",
        "mov    rsi, rcx",
        "mov    eax, 19",                   // DebugWrite
        "syscall",
        "ret",
    )
}

// The program's data, in its own `global_asm!` rather than inside the naked
// function. Switching sections in the middle of a function body is what LLVM
// refuses ("size expression must be absolute"): it is still trying to compute
// how long `_start` is, and a `.bss` label in the middle of it has no answer.
//
// The strings live in `.data` and not `.rodata` on purpose. `_start` stamps the
// process id into one of them, so the program cannot get past its first line
// unless the loader mapped the second segment writable — and it is a *private*
// copy per task, so the two do not overwrite each other's digit.
core::arch::global_asm!(
    r#"
.section .data
.globl staros_user_msg_running
staros_user_msg_running:
    .asciz "user ?: running at 0x400000 in its own address space\n"
.globl staros_user_msg_touching_zero
staros_user_msg_touching_zero:
    .asciz "user 2: dereferencing address zero, which nothing maps here\n"
.globl staros_user_msg_survived
staros_user_msg_survived:
    .asciz "user 1: still running after its neighbour faulted\n"
.globl staros_user_msg_dirty_bss
staros_user_msg_dirty_bss:
    .asciz "user 1: BSS ARRIVED DIRTY - the loader did not zero the tail\n"

/* The only reason p_memsz exceeds p_filesz for the writable segment, and the
   only thing that can tell a loader which zeroes the tail from one that hands
   over whatever the frame last held. Checked by `_start`. */
.section .bss
.globl staros_user_bss_probe
staros_user_bss_probe:
    .zero 8
"#
);

// ---------------------------------------------------------------------------
// Phase 3.3: the four roles that talk to each other.
// ---------------------------------------------------------------------------

/// Syscall numbers. The same contract `staros_abi::syscall::Syscall` states, and
/// necessarily *restated* rather than imported: this file is compiled on its own
/// by `build.rs`, with no dependencies at all, which is what makes it a program
/// the kernel loads rather than code the kernel contains.
mod sys {
    /// Send a message to an endpoint.
    pub const SEND: u64 = 1;
    /// Receive a message from an endpoint.
    pub const RECV: u64 = 2;
    /// Terminate the calling task.
    pub const EXIT: u64 = 4;
    /// Destroy the object a handle names, for every holder.
    pub const REVOKE: u64 = 6;
    /// Write a byte buffer to the debug console as one message.
    pub const DEBUG_WRITE: u64 = 19;
}

/// The IPC message, laid out exactly as `staros_ipc::Message`.
///
/// `repr(C)` is load bearing on both sides: the kernel copies this struct in and
/// out of ring-3 memory byte for byte, so Rust's freedom to reorder fields would
/// be a silent ABI break — the tag would arrive as part of a payload word.
#[repr(C)]
#[derive(Clone, Copy)]
struct Message {
    /// Caller-defined request tag.
    tag: u64,
    /// Inline payload.
    words: [u64; 4],
    /// A capability handle travelling with the message: the sender's own on the
    /// way in, the receiver's freshly installed one on the way out. Zero — the
    /// null handle — when the message carries no capability.
    cap: u32,
}

impl Message {
    const fn new(tag: u64) -> Self {
        Self {
            tag,
            words: [0; 4],
            cap: 0,
        }
    }
}

/// A syscall with two arguments. `RCX` and `R11` are destroyed by the
/// instruction itself, and the kernel may clobber memory, so both are declared.
///
/// # Safety
/// The arguments must be what the named syscall expects; a pointer argument must
/// point at memory of the right size in this address space.
unsafe fn syscall2(n: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    // SAFETY: forwarded from this function's contract.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a0,
            in("rsi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            clobber_abi("sysv64"),
        );
    }
    ret
}

/// Write a string to the debug console as one atomic message.
fn puts(s: &str) {
    // SAFETY: `DebugWrite` takes a pointer and a length into the caller's own
    // memory; both come from a live `&str` in this program's image.
    unsafe {
        syscall2(sys::DEBUG_WRITE, s.as_ptr() as u64, s.len() as u64);
    }
}

/// A small decimal formatter, because there is no `alloc` and no `core::fmt`
/// machinery worth pulling into a program this size.
///
/// Writes into `buf` from the right and returns the populated tail. Handles
/// negative values, which matters: the interesting number this program prints is
/// an error code.
fn itoa(mut v: i64, buf: &mut [u8; 24]) -> &str {
    let negative = v < 0;
    let mut at = buf.len();
    if v == 0 {
        at -= 1;
        buf[at] = b'0';
    }
    while v != 0 {
        at -= 1;
        // Taking the remainder before negating keeps `i64::MIN` from overflowing,
        // which is the one input that turns a formatter into a panic.
        let digit = (v % 10).unsigned_abs() as u8;
        buf[at] = b'0' + digit;
        v /= 10;
    }
    if negative {
        at -= 1;
        buf[at] = b'-';
    }
    // SAFETY: every byte written above is ASCII.
    unsafe { core::str::from_utf8_unchecked(&buf[at..]) }
}

/// Print `prefix`, a number, and `suffix` as one console message.
///
/// One `DebugWrite` rather than three, because the kernel's console lock is held
/// for the whole of a single call — and a line assembled from three calls is a
/// line another task can be interleaved into.
fn say_num(prefix: &str, value: i64, suffix: &str) {
    let mut line = [0u8; 192];
    let mut digits = [0u8; 24];
    let number = itoa(value, &mut digits);
    let mut at = 0;
    for part in [prefix, number, suffix] {
        let bytes = part.as_bytes();
        let room = line.len() - at;
        let n = if bytes.len() < room { bytes.len() } else { room };
        line[at..at + n].copy_from_slice(&bytes[..n]);
        at += n;
    }
    // SAFETY: `line` holds a prefix of three `&str`s copied whole or truncated at
    // an index that is a character boundary for the ASCII this program uses.
    unsafe {
        syscall2(sys::DEBUG_WRITE, line.as_ptr() as u64, at as u64);
    }
}

/// Send `msg` on the endpoint named by `handle`.
fn send(handle: u32, msg: &Message) -> i64 {
    // SAFETY: `Send` takes a handle and a pointer to one `Message` in the
    // caller's memory; `msg` is exactly that.
    unsafe { syscall2(sys::SEND, u64::from(handle), (msg as *const Message) as u64) }
}

/// Receive into `msg` on the endpoint named by `handle`, blocking until something
/// arrives.
fn recv(handle: u32, msg: &mut Message) -> i64 {
    // SAFETY: as `send`, with a buffer this program owns and may write.
    unsafe { syscall2(sys::RECV, u64::from(handle), (msg as *mut Message) as u64) }
}

/// Destroy the object `handle` names, for every task holding a capability to it.
fn revoke(handle: u32) -> i64 {
    // SAFETY: `Revoke` takes a handle and reads no memory.
    unsafe { syscall2(sys::REVOKE, u64::from(handle), 0) }
}

/// Terminate this task.
fn exit() -> ! {
    // SAFETY: `Exit` never returns and touches no memory.
    unsafe {
        syscall2(sys::EXIT, 0, 0);
    }
    // The kernel does not come back from `Exit`; if it ever did, faulting here is
    // better than falling off the end of a `-> !` function.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// The kernel's tick counter, mapped read-only into every task at a fixed
/// address. The only clock a ring-3 program has in this phase.
fn ticks() -> u64 {
    // SAFETY: the kernel maps this page read-only into every address space
    // (`addrspace::USER_CLOCK_VA`) before the task is ever scheduled.
    unsafe { (0x4_0001_0000u64 as *const u64).read_volatile() }
}

/// Spin in ring 3 until the kernel's clock has advanced by `n` ticks.
///
/// Deliberately *not* a `Yield` loop. The point in the storm is to be absent for
/// a while so the senders fill the ring and block, and a task that yields is
/// still runnable — it would be picked again the moment the senders parked, which
/// is exactly the state the wait exists to produce.
fn spin_ticks(n: u64) {
    let until = ticks() + n;
    while ticks() < until {
        core::hint::spin_loop();
    }
}

/// How many messages each storm sender sends.
const STORM_EACH: u64 = 16;
/// How many storm senders there are. Ids 5, 6 and 7.
const STORM_SENDERS: u64 = 3;
/// Sum of `1..=STORM_EACH` — what each sender's sequence must add up to at the
/// sink if nothing was lost, duplicated or reordered.
const STORM_SUM: u64 = STORM_EACH * (STORM_EACH + 1) / 2;

/// Entry for every phase-3.3 role. `id` is the process id byte the kernel seeded.
///
/// The capability layout each role is given is fixed by `usermode::selftest_ipc`
/// and known here by role, which is what a handle *is*: an index into this task's
/// own table, meaningless in anyone else's, and never guessable — the delegated
/// one below is not written down anywhere, it arrives inside a message.
///
/// Called once, from `_start`, with the id in `EDI`; it never returns.
#[no_mangle]
extern "C" fn staros_user_roles(id: u64) -> ! {
    match id {
        3 => server(),
        4 => client(),
        8 => storm_sink(),
        _ => storm_sender(id),
    }
}

/// The server. Holds: 1 = request (receive), 2 = reply (send), 3 = the delegated
/// endpoint's *receive* rights, 4 = the same endpoint's *send* rights, which is
/// the capability it hands out.
///
/// Two capabilities on one object rather than one with both rights, because
/// delegation must not be able to give away more than intended. The kernel
/// carries whatever capability the sender names; a server that held send *and*
/// receive in one handle and delegated it would have handed the client the right
/// to steal its own requests.
fn server() -> ! {
    // Be busy first. The server is spawned before the client and would otherwise
    // already be parked in `recv` when the first request arrives — so the first
    // message goes straight to a waiting receiver, the next two fit the ring, and
    // the client's third send never has to wait for anything. The blocking-send
    // path would then be exercised only by the storm, and the client's line about
    // its third request waiting for a slot would be a sentence with nothing
    // behind it. Two ticks of being unavailable is what makes it true.
    spin_ticks(2);

    let mut msg = Message::new(0);
    let mut tags = [0u64; 3];
    for slot in &mut tags {
        if recv(1, &mut msg) != 0 {
            puts("[server] RECEIVE FAILED on the request endpoint\n");
            exit();
        }
        *slot = msg.tag;
    }
    if tags != [1, 2, 3] {
        puts("[server] REQUESTS ARRIVED OUT OF ORDER\n");
        exit();
    }
    puts("[server] 3 requests received in order, one of them from a blocked sender\n");

    // The reply that carries authority. `cap` names *this task's* handle 4; what
    // the client receives is a handle of its own that the kernel allocates.
    let mut reply = Message::new(101);
    reply.cap = 4;
    if send(2, &reply) != 0 {
        puts("[server] REPLY FAILED\n");
        exit();
    }
    puts("[server] delegated send rights on its private endpoint, inside a reply\n");

    if recv(3, &mut msg) != 0 || msg.tag != 10 {
        puts("[server] THE DELEGATED ENDPOINT CARRIED NOTHING\n");
        exit();
    }
    puts("[server] the client used the delegated capability: tag 10 arrived\n");

    // Pull it back. Nothing touches the client's table — the object itself stops
    // existing, and every capability naming it, here and there, stops resolving.
    let rc = revoke(3);
    if rc != 0 {
        say_num("[server] REVOKE FAILED rc=", rc, "\n");
        exit();
    }
    puts("[server] revoked the delegated endpoint for every holder\n");

    // Tell the client to try again, so its failure is one it went looking for.
    let _ = send(2, &Message::new(103));

    // The server's own handle 4 named the same object, and it is just as dead.
    // Asserting that is what separates a revocation from a permission check on
    // the receiving side.
    let rc = send(4, &Message::new(11));
    if rc != -2 {
        say_num("[server] ITS OWN HANDLE STILL WORKS AFTER REVOCATION rc=", rc, "\n");
        exit();
    }
    puts("[server] its own second handle to that object is dead too\n");
    exit()
}

/// The client. Holds: 1 = request (send), 2 = reply (receive). It is granted no
/// access at all to the endpoint it ends up using — that arrives at run time.
fn client() -> ! {
    // Three requests into a two-slot ring. The third cannot be buffered and
    // cannot be handed to a receiver, so this task parks inside the syscall until
    // the server drains a slot. Nothing here asked to block, and the program
    // cannot tell that it did — which is the property being demonstrated.
    for tag in 1..=3 {
        if send(1, &Message::new(tag)) != 0 {
            puts("[client] SEND FAILED\n");
            exit();
        }
    }
    puts("[client] 3 requests sent into a 2-slot ring; the third waited for a slot\n");

    let mut msg = Message::new(0);
    if recv(2, &mut msg) != 0 || msg.tag != 101 {
        puts("[client] NO REPLY\n");
        exit();
    }
    let delegated = msg.cap;
    if delegated == 0 {
        puts("[client] THE REPLY CARRIED NO CAPABILITY\n");
        exit();
    }
    say_num("[client] reply 101 carried a capability, installed as handle ", i64::from(delegated), "\n");

    // Authority this task did not have when it started, exercised.
    if send(delegated, &Message::new(10)) != 0 {
        puts("[client] THE DELEGATED CAPABILITY DID NOT WORK\n");
        exit();
    }
    puts("[client] sent through the delegated capability\n");

    // Wait for the server to say it has revoked, then use the same handle again.
    if recv(2, &mut msg) != 0 || msg.tag != 103 {
        puts("[client] NO REVOCATION NOTICE\n");
        exit();
    }
    let rc = send(delegated, &Message::new(12));
    if rc != -2 {
        say_num("[client] THE REVOKED HANDLE STILL WORKS rc=", rc, "\n");
        exit();
    }
    puts("[client] the same handle now answers BadHandle: the object was revoked, not the handle\n");
    exit()
}

/// One of three tasks hammering a two-slot endpoint. Holds: 1 = storm (send).
///
/// Each message carries its sender's id as the tag and a strictly increasing
/// sequence number, which is what lets the sink check that the ring kept one
/// sender's messages in order while interleaving three senders' arbitrarily.
fn storm_sender(id: u64) -> ! {
    for seq in 1..=STORM_EACH {
        let mut msg = Message::new(id);
        msg.words[0] = seq;
        if send(1, &msg) != 0 {
            puts("[storm] SEND FAILED\n");
            exit();
        }
    }
    exit()
}

/// The other end of the storm. Holds: 1 = storm (receive).
///
/// Starts by staying away for a few ticks. That is not politeness: with a
/// two-slot ring and three senders, a sink that receives immediately can keep up,
/// and the blocking-send path — park the sender, hand its message to the receiver
/// that frees the slot, wake it — might never run. Being absent guarantees every
/// sender blocks at least once.
fn storm_sink() -> ! {
    spin_ticks(5);

    let total = STORM_EACH * STORM_SENDERS;
    let mut sums = [0u64; STORM_SENDERS as usize];
    let mut last = [0u64; STORM_SENDERS as usize];
    let mut out_of_order = 0u64;
    let mut wrong_sender = 0u64;

    let mut msg = Message::new(0);
    for _ in 0..total {
        if recv(1, &mut msg) != 0 {
            puts("[ipc-storm] RECEIVE FAILED\n");
            exit();
        }
        // Senders are ids 5, 6 and 7; the tag is the sender's id.
        let Some(which) = msg.tag.checked_sub(5).filter(|w| *w < STORM_SENDERS) else {
            wrong_sender += 1;
            continue;
        };
        let which = which as usize;
        let seq = msg.words[0];
        // One sender's messages must arrive in the order it sent them. Three
        // senders interleaving arbitrarily is expected; a single sender's second
        // message overtaking its first would mean the ring reordered, which is the
        // one thing a channel may not do.
        if seq <= last[which] {
            out_of_order += 1;
        }
        last[which] = seq;
        sums[which] += seq;
    }

    if wrong_sender != 0 {
        say_num("[ipc-storm] FAILED: messages from an unknown sender: ", wrong_sender as i64, "\n");
        exit();
    }
    if out_of_order != 0 {
        say_num("[ipc-storm] FAILED: out-of-order arrivals: ", out_of_order as i64, "\n");
        exit();
    }
    let mut total_sum = 0u64;
    for sum in sums {
        if sum != STORM_SUM {
            say_num("[ipc-storm] FAILED: a sender's sequence summed to ", sum as i64, "\n");
            exit();
        }
        total_sum += sum;
    }
    say_num(
        "[ipc-storm] ",
        total as i64,
        " messages received from 3 senders, in order per sender\n",
    );
    say_num("[ipc-storm] sequence sum exact: ", total_sum as i64, "\n");
    exit()
}

// The memory intrinsics LLVM is entitled to call for a slice copy or a zeroed
// array, and which nothing else here provides: the program links with `rust-lld`
// against no libc, and the pre-compiled `core` for the host target deliberately
// does not carry them (that is what `compiler-builtins-mem` is for, and it is a
// cargo feature this single-file `rustc` build has no way to ask for).
//
// Byte-at-a-time on purpose. They move a few hundred bytes in the whole life of
// this program — a line buffer and a 48-byte message — and a clever version would
// be code with nothing checking it.

/// # Safety
/// `dest` and `src` must be valid for `n` bytes and must not overlap.
#[no_mangle]
unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        // SAFETY: forwarded from this function's contract; `i < n`.
        unsafe { *dest.add(i) = *src.add(i) };
        i += 1;
    }
    dest
}

/// # Safety
/// `dest` and `src` must be valid for `n` bytes. Overlap is permitted.
#[no_mangle]
unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // Copy backwards when the regions overlap with `dest` above `src`, which is
    // the one direction a forward copy would corrupt.
    if (dest as usize) > (src as usize) && (dest as usize) < (src as usize) + n {
        let mut i = n;
        while i > 0 {
            i -= 1;
            // SAFETY: forwarded from this function's contract; `i < n`.
            unsafe { *dest.add(i) = *src.add(i) };
        }
    } else {
        let mut i = 0;
        while i < n {
            // SAFETY: as above.
            unsafe { *dest.add(i) = *src.add(i) };
            i += 1;
        }
    }
    dest
}

/// # Safety
/// `dest` must be valid for `n` bytes.
#[no_mangle]
unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let byte = c as u8;
    let mut i = 0;
    while i < n {
        // SAFETY: forwarded from this function's contract; `i < n`.
        unsafe { *dest.add(i) = byte };
        i += 1;
    }
    dest
}

/// # Safety
/// `a` and `b` must be valid for `n` bytes.
#[no_mangle]
unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        // SAFETY: forwarded from this function's contract; `i < n`.
        let (x, y) = unsafe { (*a.add(i), *b.add(i)) };
        if x != y {
            return i32::from(x) - i32::from(y);
        }
        i += 1;
    }
    0
}

/// The personality routine an unwinder would call. There is no unwinder here —
/// the program is built with `-Cpanic=abort` — but the pre-compiled `core` for
/// the host target carries a reference to this symbol in its metadata, and the
/// linker resolves references before it decides nothing calls them.
///
/// Present only since phase 3.3: until the roles above existed, no `core` code
/// was instantiated at all and the reference never appeared.
#[no_mangle]
extern "C" fn rust_eh_personality() {}

/// Nothing in this program panics — the roles above use no fallible `core`
/// operation — but `no_std` requires the lang item to exist.
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    // No console without a syscall, and no syscall without registers this
    // handler can be sure of. Spin: the kernel's timer will preempt and the task
    // can be observed as stuck rather than as silently gone.
    loop {
        core::hint::spin_loop();
    }
}
