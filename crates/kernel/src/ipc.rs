//! Synchronous message-passing endpoints — the microkernel's core mechanism.
//!
//! In a microkernel the kernel keeps almost no policy; what it *must* provide is
//! a way for isolated tasks — which share no memory — to communicate. That is an
//! endpoint: a rendezvous point a task can [`send`] to and [`recv`] from. The
//! message is copied *through the kernel*; neither side can touch the other's
//! memory, and from phase 3.2 neither side's pages are even mapped while the
//! other runs.
//!
//! A message may also **transfer a capability**: the sender names one of its own
//! capabilities in `Message.cap`, the kernel carries the *resolved* [`Cap`]
//! (handles are per-task and meaningless across the boundary), and the receiver
//! has it installed into its table under a fresh handle. That is how one service
//! hands another the authority to talk to it, without the kernel knowing either
//! of them.
//!
//! ## Queueing policy
//! Each endpoint has a bounded ring plus wait queues for blocked receivers *and*
//! blocked senders. [`recv`] returns a buffered message or blocks; [`send`]
//! delivers straight to a waiting receiver, else buffers, else — if the ring is
//! full — blocks the sender until a receiver drains a slot. The ring is
//! deliberately tiny (two slots) so the blocking-send path is *exercised* rather
//! than hidden behind a buffer large enough that no demo ever fills it.
//!
//! ## The lock rule
//! The endpoint lock is held for the **decision** only, never across a context
//! switch. Both functions below decide what to do under a short borrow, drop the
//! guard, and only then block, deliver or wake. A guard held across
//! [`sched::block_current`] would leave the lock owned by a task that is no
//! longer running, and the next taker would wait for it for ever — a deadlock
//! whose symptom is a boot that simply stops.

use core::sync::atomic::{AtomicU64, Ordering};

use staros_abi::error::KError;
use staros_ipc::Message;

use crate::cap::Cap;
use crate::kprintln;
use crate::sched;
use crate::sync::SpinLock;

/// Number of endpoints the kernel exposes.
///
/// Four, and each one is minted by `usermode::selftest` and used by a ring-3
/// task: the client's request and reply pair, the endpoint the server *delegates*
/// mid-conversation, and the one three senders hammer at once. A real system
/// allocates these on demand; this tree does not have the syscall for it yet, and
/// a table sized for hypothetical future users would be a number with nothing
/// behind it.
///
/// The ids are a *shared numbering* between this table and whoever creates the
/// objects, which is exactly the kind of seam that bites: an endpoint object with
/// an id past the end of this array is a perfectly well-formed object that no
/// send or receive can ever use. [`endpoint_exists`] is what closes it.
pub const NUM_ENDPOINTS: usize = 4;

/// Client → server requests.
pub const REQUEST_EP: usize = 0;
/// Server → client replies, and the message that carries the delegated capability.
pub const REPLY_EP: usize = 1;
/// The endpoint the client is *given* authority over at run time, and which is
/// then revoked out from under it.
pub const DELEGATED_EP: usize = 2;
/// The endpoint several senders contend on. Its blocked sends are not logged —
/// there are dozens by design, and they would bury every other line.
pub const STORM_EP: usize = 3;

/// Whether `id` names a slot in this table.
///
/// Asked by [`obj::create`](crate::obj::create) before it makes an endpoint
/// object, so that a mismatched id fails on the line that wrote the number rather
/// than inside a server that has already announced itself.
#[must_use]
pub const fn endpoint_exists(id: usize) -> bool {
    id < NUM_ENDPOINTS
}

/// Capacity of an endpoint's pending-message ring. Deliberately tiny so the
/// blocking-send path is exercised rather than hidden.
const RING_CAP: usize = 2;

/// Maximum tasks that can be blocked, in each direction, on one endpoint at once.
const MAX_WAITERS: usize = 4;

/// A message as the kernel carries it: the user-visible [`Message`] plus the
/// resolved capability being transferred, if any. `Copy`, so the send path never
/// allocates.
#[derive(Clone, Copy)]
pub struct KMessage {
    /// The bytes delivered into the receiver's buffer.
    pub msg: Message,
    /// A capability transferred with the message, already resolved from the
    /// sender's table into a kernel object; installed into the receiver's table
    /// on delivery. `None` if the message transfers no capability.
    pub cap: Option<Cap>,
}

impl KMessage {
    /// An empty slot's contents. Not a valid message — it is what an unused ring
    /// entry holds, and `len`/`head` are what say which entries are real.
    pub const fn empty() -> Self {
        Self {
            msg: Message::new(0),
            cap: None,
        }
    }
}

/// A rendezvous point: a bounded message ring plus queues of blocked receivers
/// and blocked senders (the latter carrying the message they could not deposit).
struct Endpoint {
    ring: [KMessage; RING_CAP],
    head: usize,
    len: usize,
    recv_waiters: [usize; MAX_WAITERS],
    n_recv: usize,
    send_waiters: [(usize, KMessage); MAX_WAITERS],
    n_send: usize,
}

impl Endpoint {
    const fn new() -> Self {
        Self {
            ring: [KMessage::empty(); RING_CAP],
            head: 0,
            len: 0,
            recv_waiters: [0; MAX_WAITERS],
            n_recv: 0,
            send_waiters: [(0, KMessage::empty()); MAX_WAITERS],
            n_send: 0,
        }
    }

    /// Buffer `km`, or fail if the ring is full.
    fn push_msg(&mut self, km: KMessage) -> bool {
        if self.len == RING_CAP {
            return false;
        }
        let tail = (self.head + self.len) % RING_CAP;
        self.ring[tail] = km;
        self.len += 1;
        true
    }

    /// Take the oldest buffered message. First in, first out — a ring that
    /// returned the newest would reorder one sender's own messages, which is the
    /// one thing a channel may never do.
    fn pop_msg(&mut self) -> Option<KMessage> {
        if self.len == 0 {
            return None;
        }
        let km = self.ring[self.head];
        self.head = (self.head + 1) % RING_CAP;
        self.len -= 1;
        Some(km)
    }

    fn push_recv_waiter(&mut self, task: usize) -> bool {
        if self.n_recv == MAX_WAITERS {
            return false;
        }
        self.recv_waiters[self.n_recv] = task;
        self.n_recv += 1;
        true
    }

    fn pop_recv_waiter(&mut self) -> Option<usize> {
        if self.n_recv == 0 {
            return None;
        }
        let task = self.recv_waiters[0];
        self.recv_waiters.copy_within(1..self.n_recv, 0);
        self.n_recv -= 1;
        Some(task)
    }

    fn push_send_waiter(&mut self, task: usize, km: KMessage) -> bool {
        if self.n_send == MAX_WAITERS {
            return false;
        }
        self.send_waiters[self.n_send] = (task, km);
        self.n_send += 1;
        true
    }

    fn pop_send_waiter(&mut self) -> Option<(usize, KMessage)> {
        if self.n_send == 0 {
            return None;
        }
        let waiter = self.send_waiters[0];
        self.send_waiters.copy_within(1..self.n_send, 0);
        self.n_send -= 1;
        Some(waiter)
    }

    /// Drop `task` from both wait queues, reporting whether it was on either.
    ///
    /// Called when a task dies while parked on an endpoint. Without it the queue
    /// holds the slot index of a dead task, and the next send hands a message to
    /// a corpse: `deliver` writes into a slot whose stack has been reaped and
    /// whose address space no longer exists. Nothing about that is visible until
    /// it happens, which is why it is done for every dying task rather than only
    /// for ones the demo expects to be blocked.
    fn remove_waiter(&mut self, task: usize) -> bool {
        let mut found = false;
        let mut w = 0;
        while w < self.n_recv {
            if self.recv_waiters[w] == task {
                self.recv_waiters.copy_within(w + 1..self.n_recv, w);
                self.n_recv -= 1;
                found = true;
            } else {
                w += 1;
            }
        }
        let mut s = 0;
        while s < self.n_send {
            if self.send_waiters[s].0 == task {
                self.send_waiters.copy_within(s + 1..self.n_send, s);
                self.n_send -= 1;
                found = true;
            } else {
                s += 1;
            }
        }
        found
    }
}

/// The endpoint table. See the module docs for why the lock never spans a switch.
static IPC: SpinLock<[Endpoint; NUM_ENDPOINTS]> =
    SpinLock::new([const { Endpoint::new() }; NUM_ENDPOINTS]);

/// Messages that went straight from a sender to an already-waiting receiver.
static DELIVERED: AtomicU64 = AtomicU64::new(0);
/// Messages that were buffered because no receiver was waiting.
static BUFFERED: AtomicU64 = AtomicU64::new(0);
/// Sends that had to block because the ring was full, **per endpoint**.
///
/// The number this phase cares about most, and per endpoint rather than in total
/// because a total is a check that does not check. Widening the ring from two
/// slots to eight leaves the storm — forty-eight messages against a sink that
/// stays away — still blocking seven times, so a total-only assertion passes
/// while the client's request path, the one the boot log narrates as "the third
/// waited for a slot", never blocks at all. Per endpoint, that same change fails
/// on the request endpoint immediately.
static SEND_BLOCKS: [AtomicU64; NUM_ENDPOINTS] = [const { AtomicU64::new(0) }; NUM_ENDPOINTS];
/// Receives that had to block because the ring was empty.
static RECV_BLOCKS: AtomicU64 = AtomicU64::new(0);
/// Capabilities transferred over IPC.
static CAPS_MOVED: AtomicU64 = AtomicU64::new(0);

/// Sends that completed, and receives that returned a message.
///
/// The pair that has to balance, and neither of the three counters above can
/// stand in for it. A send that blocks is counted in none of them at the moment
/// it happens — its message is held in a wait queue, neither delivered nor
/// buffered — and it is buffered later by the *receive* that frees a slot. So
/// `delivered + buffered` undercounts a run by exactly the number of sends that
/// had to wait, which is a number that changes with timing.
static SENT: AtomicU64 = AtomicU64::new(0);
static RECEIVED: AtomicU64 = AtomicU64::new(0);

/// `(sent, received, delivered, buffered, send blocks, recv blocks, caps)`.
#[must_use]
pub fn stats() -> Stats {
    Stats {
        sent: SENT.load(Ordering::Relaxed),
        received: RECEIVED.load(Ordering::Relaxed),
        delivered: DELIVERED.load(Ordering::Relaxed),
        buffered: BUFFERED.load(Ordering::Relaxed),
        send_blocks: SEND_BLOCKS.iter().map(|c| c.load(Ordering::Relaxed)).sum(),
        recv_blocks: RECV_BLOCKS.load(Ordering::Relaxed),
        caps_moved: CAPS_MOVED.load(Ordering::Relaxed),
    }
}

/// What the endpoints have done so far. A struct rather than a tuple because
/// seven numbers positionally is how a caller reports blocked receives as
/// transferred capabilities.
#[derive(Clone, Copy)]
pub struct Stats {
    /// Sends that completed, including those that had to wait for a slot.
    pub sent: u64,
    /// Receives that returned a message.
    pub received: u64,
    /// Messages handed straight to an already-waiting receiver.
    pub delivered: u64,
    /// Messages that went into a ring because nobody was waiting.
    pub buffered: u64,
    /// Sends that parked because the ring was full, across every endpoint.
    pub send_blocks: u64,
    /// Receives that parked because the ring was empty.
    pub recv_blocks: u64,
    /// Capabilities carried across an endpoint.
    pub caps_moved: u64,
}

/// What [`send`] decided to do, once the lock is dropped.
enum SendAction {
    /// Hand it straight to this blocked receiver.
    Deliver(usize),
    /// It went into the ring.
    Buffered,
    /// The ring was full; the caller is now a registered send waiter and must park.
    Block,
    /// The ring was full and the send queue too. Nothing was queued.
    Full,
}

/// Send `km` to endpoint `ep`. Delivers straight to a blocked receiver, else
/// buffers it, else — if the ring is full — blocks the caller until a receiver
/// drains a slot. Returns `0` on success (possibly after blocking) or a negative
/// [`KError`].
pub fn send(ep: usize, km: KMessage) -> isize {
    if ep >= NUM_ENDPOINTS {
        return KError::InvalidArgument.as_raw();
    }
    let me = sched::current_id();

    // Decide under a short borrow; act after dropping it. The block path performs
    // a context switch and must not be holding this lock when it does.
    let action = {
        let mut table = IPC.lock();
        let e = &mut table[ep];
        if let Some(w) = e.pop_recv_waiter() {
            SendAction::Deliver(w)
        } else if e.push_msg(km) {
            SendAction::Buffered
        } else if e.push_send_waiter(me, km) {
            SendAction::Block
        } else {
            SendAction::Full
        }
    };

    if km.cap.is_some() && !matches!(action, SendAction::Full) {
        CAPS_MOVED.fetch_add(1, Ordering::Relaxed);
    }

    match action {
        SendAction::Deliver(w) => {
            DELIVERED.fetch_add(1, Ordering::Relaxed);
            SENT.fetch_add(1, Ordering::Relaxed);
            sched::deliver(w, km);
            0
        }
        SendAction::Buffered => {
            BUFFERED.fetch_add(1, Ordering::Relaxed);
            SENT.fetch_add(1, Ordering::Relaxed);
            0
        }
        SendAction::Block => {
            SEND_BLOCKS[ep].fetch_add(1, Ordering::Relaxed);
            // The storm endpoint blocks dozens of times by design; logging each
            // one would drown every other line in the boot output. Its evidence
            // is the tally, not a narrative.
            if ep != STORM_EP {
                kprintln!("[ipc] task {me} send blocked: ep{ep} ring full");
            }
            sched::block_current();
            // Counted on the way *out*, not on the way in: until the receiver
            // took this message out of the wait queue and put it in the ring, the
            // send had not happened. A sender still parked at the end of a run is
            // therefore missing from this count, which is what makes it balance
            // against `RECEIVED` only when nothing was left in flight.
            SENT.fetch_add(1, Ordering::Relaxed);
            if ep != STORM_EP {
                kprintln!("[ipc] task {me} send resumed");
            }
            0
        }
        SendAction::Full => KError::OutOfResources.as_raw(),
    }
}

/// How many sends had to wait for a slot on endpoint `ep`.
///
/// Zero for an endpoint the phase says should have blocked means the ring was
/// never full there, whatever the totals say. See [`SEND_BLOCKS`].
#[must_use]
pub fn send_blocks_on(ep: usize) -> u64 {
    SEND_BLOCKS.get(ep).map_or(0, |c| c.load(Ordering::Relaxed))
}

/// What [`recv`] decided to do, once the lock is dropped.
enum RecvAction {
    /// A buffered message, and nobody was waiting to deposit another.
    Got(KMessage),
    /// A buffered message, and a blocked sender's message took the slot it freed.
    WakeSender(KMessage, usize),
    /// Nothing buffered; the caller is now a registered receive waiter and must park.
    Block,
    /// Nothing buffered and the receive queue is full.
    Full,
}

/// Receive from endpoint `ep`: return a buffered message, or block until one
/// arrives. Draining a slot wakes a blocked sender, moving its message into the
/// slot just freed — which is what keeps a blocked sender's message ahead of any
/// send that arrives afterwards.
///
/// # Errors
/// [`KError::InvalidArgument`] for an endpoint that does not exist,
/// [`KError::OutOfResources`] when the receive queue is full.
pub fn recv(ep: usize) -> Result<KMessage, KError> {
    if ep >= NUM_ENDPOINTS {
        return Err(KError::InvalidArgument);
    }
    let me = sched::current_id();

    let action = {
        let mut table = IPC.lock();
        let e = &mut table[ep];
        match e.pop_msg() {
            Some(km) => match e.pop_send_waiter() {
                // We freed a slot; let a blocked sender deposit its message.
                Some((tid, skm)) => {
                    e.push_msg(skm);
                    RecvAction::WakeSender(km, tid)
                }
                None => RecvAction::Got(km),
            },
            None if e.push_recv_waiter(me) => RecvAction::Block,
            None => RecvAction::Full,
        }
    };

    match action {
        RecvAction::Got(km) => {
            RECEIVED.fetch_add(1, Ordering::Relaxed);
            Ok(km)
        }
        RecvAction::WakeSender(km, tid) => {
            RECEIVED.fetch_add(1, Ordering::Relaxed);
            sched::unblock(tid);
            Ok(km)
        }
        RecvAction::Block => {
            RECV_BLOCKS.fetch_add(1, Ordering::Relaxed);
            let km = sched::block_for_message();
            RECEIVED.fetch_add(1, Ordering::Relaxed);
            Ok(km)
        }
        RecvAction::Full => Err(KError::OutOfResources),
    }
}

/// Where task `task` is waiting: `(endpoint, is_send)`, or `None` if it is on no
/// wait queue.
///
/// The scheduler can say a task is blocked; it cannot say *what for*, because the
/// wait queues live here. The difference matters the first time a program stalls
/// rather than a server: a client parked on its reply endpoint is owed an answer,
/// and a client parked on a request endpoint is waiting for something it will
/// never be sent — the same word, two different defects.
#[must_use]
pub fn waiting_on(task: usize) -> Option<(usize, bool)> {
    let ipc = IPC.lock();
    for (ep, e) in ipc.iter().enumerate() {
        if e.recv_waiters[..e.n_recv].contains(&task) {
            return Some((ep, false));
        }
        if e.send_waiters[..e.n_send].iter().any(|&(t, _)| t == task) {
            return Some((ep, true));
        }
    }
    None
}

/// Remove `task` from every wait queue it stands in, returning how many queues it
/// was on.
///
/// Called by the scheduler when a task dies. A task can die while parked — a
/// ring-3 fault kills it wherever it is — and a queue entry naming a dead slot is
/// a message handed to a task whose stack has been reclaimed and whose address
/// space has been torn down.
pub fn forget_task(task: usize) -> usize {
    let mut ipc = IPC.lock();
    let mut queues = 0;
    for e in ipc.iter_mut() {
        if e.remove_waiter(task) {
            queues += 1;
        }
    }
    queues
}
