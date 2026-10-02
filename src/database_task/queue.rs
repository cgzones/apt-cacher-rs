//! Observe DB queue capacity at send/receive boundaries, including cancellation.
//!
//! A span at the cap starts only when a sender finds the queue full and so
//! has to wait; a send that merely fills the final slot starts none. Every
//! later observation that finds room ends the span. The capacity read and clock transition share a short lock, so a delayed
//! observation cannot start an idle clock or stop a refilled one based on
//! an older sample. Channel operations remain asynchronous and unlocked.
//! These are observations, not a replacement for Tokio's channel: a brief
//! full-to-drained transition between observations can still be missed.
//!
//! The common observation (room, no span running) skips the lock: it would
//! only record the depth peak, an order-free maximum, and leave an idle
//! clock. It changes no clock state, so it cannot start or stop a span from
//! an older sample either; what it can miss is a span a sender starts
//! (under the lock, from its own full sample) just after the unlocked check
//! found the clock idle. That span ends at the next observation finding
//! room, at the latest that sender's own once its send completes.

use std::ops::Deref;

use tokio::sync::mpsc::{
    Receiver, Sender, error::SendError, error::TryRecvError, error::TrySendError,
};

use crate::metrics;

pub(super) struct QueueObserver<'a> {
    sampling: parking_lot::Mutex<()>,
    clock: &'a metrics::CapClock,
}

/// What an observation may do to the clock.
#[derive(Clone, Copy)]
enum Observation {
    /// A sender about to send: a full queue makes it wait, so it starts
    /// the span.
    Admission,
    /// After a send, a receive, a cancelled send or closure: room ends the
    /// span, but a queue filled without a sender waiting starts none.
    Settlement,
}

struct Snapshot {
    capacity: usize,
    max_capacity: usize,
    closed: bool,
}

impl<'a> QueueObserver<'a> {
    pub(super) const fn new(clock: &'a metrics::CapClock) -> Self {
        Self {
            sampling: parking_lot::const_mutex(()),
            clock,
        }
    }

    /// Sample inside the lock: passing an already-read capacity would let
    /// an old full sample race a newer empty sample and restart the clock.
    /// Room with no span running needs no lock (see the module docs).
    fn observe(&self, kind: Observation, read: impl Fn() -> Snapshot) -> bool {
        if !self.clock.is_at_cap() {
            let Snapshot {
                capacity,
                max_capacity,
                closed,
            } = read();
            if capacity != 0 || closed {
                metrics::DB_QUEUE_DEPTH_PEAK.update(max_capacity.saturating_sub(capacity) as u64);
                return false;
            }
        }
        let sampling = self.sampling.lock();
        let Snapshot {
            capacity,
            max_capacity,
            closed,
        } = read();
        metrics::DB_QUEUE_DEPTH_PEAK.update(max_capacity.saturating_sub(capacity) as u64);
        let full = capacity == 0 && !closed;
        match (full, kind) {
            (true, Observation::Admission) => self.clock.enter(),
            (true, Observation::Settlement) => {}
            (false, _) => self.clock.leave(),
        }
        drop(sampling);
        full
    }

    /// A sender is about to send: whether it finds the queue full and has
    /// to wait.
    pub(super) fn admit<T>(&self, tx: &Sender<T>) -> bool {
        self.observe_sender(Observation::Admission, tx)
    }

    fn observe_sender<T>(&self, kind: Observation, tx: &Sender<T>) -> bool {
        self.observe(kind, || Snapshot {
            capacity: tx.capacity(),
            max_capacity: tx.max_capacity(),
            closed: tx.is_closed(),
        })
    }

    fn observe_receiver<T>(&self, rx: &Receiver<T>) {
        self.observe(Observation::Settlement, || Snapshot {
            capacity: rx.capacity(),
            max_capacity: rx.max_capacity(),
            closed: rx.is_closed(),
        });
    }

    /// Send after [`Self::admit`] (or a `Full` [`Self::try_send`]) decided
    /// whether this sender waits.
    pub(super) async fn send<T>(&self, tx: &Sender<T>, value: T) -> Result<(), SendError<T>> {
        // The awaited send future drops before this guard on cancellation,
        // returning its reserved capacity before the final observation.
        let _observation = SendObservation { observer: self, tx };
        tx.send(value).await
    }

    pub(super) fn try_send<T>(&self, tx: &Sender<T>, value: T) -> Result<(), TrySendError<T>> {
        let result = tx.try_send(value);
        let kind = if matches!(result, Err(TrySendError::Full(_))) {
            Observation::Admission
        } else {
            Observation::Settlement
        };
        self.observe_sender(kind, tx);
        result
    }

    pub(super) fn receiver<T>(&self, inner: Receiver<T>) -> ObservedReceiver<'_, 'a, T> {
        ObservedReceiver {
            observer: self,
            inner,
        }
    }
}

struct SendObservation<'s, 'a, T> {
    observer: &'s QueueObserver<'a>,
    tx: &'s Sender<T>,
}

impl<T> Drop for SendObservation<'_, '_, T> {
    fn drop(&mut self) {
        self.observer
            .observe_sender(Observation::Settlement, self.tx);
    }
}

/// Own the receiver so task cancellation closes it before stopping its
/// clock. Late senders then observe closure and cannot restart the clock.
pub(super) struct ObservedReceiver<'s, 'a, T> {
    observer: &'s QueueObserver<'a>,
    inner: Receiver<T>,
}

impl<T> ObservedReceiver<'_, '_, T> {
    pub(super) async fn recv_many(&mut self, buffer: &mut Vec<T>, limit: usize) -> usize {
        let count = self.inner.recv_many(buffer, limit).await;
        // Account for freed capacity before the caller awaits database I/O.
        self.observer.observe_receiver(&self.inner);
        count
    }

    pub(super) fn close(&mut self) {
        self.inner.close();
        self.observer.observe_receiver(&self.inner);
    }

    pub(super) fn try_recv(&mut self) -> Result<T, TryRecvError> {
        let result = self.inner.try_recv();
        self.observer.observe_receiver(&self.inner);
        result
    }
}

impl<T> Drop for ObservedReceiver<'_, '_, T> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<T> Deref for ObservedReceiver<'_, '_, T> {
    type Target = Receiver<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, task::Poll};

    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn only_a_sender_finding_the_queue_full_starts_the_clock() {
        let clock = metrics::CapClock::new();
        let observer = QueueObserver::new(&clock);
        let (tx, rx) = mpsc::channel(2);
        let mut rx = observer.receiver(rx);
        observer.try_send(&tx, 1).expect("first slot");
        assert!(!observer.admit(&tx));
        observer.send(&tx, 2).await.expect("last slot");
        assert!(!clock.is_at_cap(), "nobody waits on the filled queue yet");
        assert!(metrics::DB_QUEUE_DEPTH_PEAK.get() >= 2);
        assert!(observer.admit(&tx));
        assert!(clock.is_at_cap());

        let mut batch = Vec::new();
        assert_eq!(rx.recv_many(&mut batch, 1).await, 1);
        assert!(!clock.is_at_cap(), "stopped before processing the batch");
        observer
            .try_send(&tx, 3)
            .expect("refill the final slot synchronously");
        assert!(!clock.is_at_cap());
        assert!(matches!(
            observer.try_send(&tx, 4),
            Err(TrySendError::Full(4))
        ));
        assert!(clock.is_at_cap());
        assert_eq!(rx.recv_many(&mut batch, 2).await, 2);
        assert!(!clock.is_at_cap());
        assert_eq!(batch, [1, 2, 3]);
    }

    #[tokio::test]
    async fn a_parked_fallback_send_observes_the_refilled_queue() {
        let clock = metrics::CapClock::new();
        let observer = QueueObserver::new(&clock);
        let (tx, rx) = mpsc::channel(1);
        let mut rx = observer.receiver(rx);
        observer.try_send(&tx, 1).expect("last slot");
        assert!(!clock.is_at_cap());
        let Err(TrySendError::Full(value)) = observer.try_send(&tx, 2) else {
            unreachable!("the full queue defers the send");
        };
        let mut waiting = Box::pin(observer.send(&tx, value));
        assert!(
            poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        let mut batch = Vec::new();
        assert_eq!(rx.recv_many(&mut batch, 1).await, 1);
        waiting.await.expect("the fallback fills the released slot");
        assert!(clock.is_at_cap());
        assert_eq!(rx.recv_many(&mut batch, 1).await, 1);
        assert!(!clock.is_at_cap());
        assert_eq!(batch, [1, 2]);
    }

    #[tokio::test]
    async fn cancelling_a_woken_sender_observes_its_released_reservation() {
        let clock = metrics::CapClock::new();
        let observer = QueueObserver::new(&clock);
        let (tx, rx) = mpsc::channel(1);
        let mut rx = observer.receiver(rx);
        observer.send(&tx, 1).await.expect("last slot");
        assert!(observer.admit(&tx));
        let mut waiting = Box::pin(observer.send(&tx, 2));
        assert!(
            poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        let mut batch = Vec::new();
        assert_eq!(rx.recv_many(&mut batch, 1).await, 1);
        assert_eq!(tx.capacity(), 0, "the parked sender owns the released slot");
        assert!(clock.is_at_cap());
        drop(waiting);
        assert_eq!(tx.capacity(), 1);
        assert!(
            !clock.is_at_cap(),
            "cancellation returned the only reservation"
        );
    }

    #[tokio::test]
    async fn closure_stops_the_clock_and_late_senders_cannot_restart_it() {
        let clock = metrics::CapClock::new();
        let observer = QueueObserver::new(&clock);
        let (tx, rx) = mpsc::channel(1);
        let mut rx = observer.receiver(rx);
        observer.send(&tx, 1).await.expect("last slot");
        assert!(observer.admit(&tx));
        let mut waiting = Box::pin(observer.send(&tx, 2));
        assert!(
            poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        rx.close();
        assert!(!clock.is_at_cap(), "closure ends the span before draining");
        assert!(!observer.admit(&tx));
        assert!(waiting.await.is_err());
        assert!(matches!(
            observer.try_send(&tx, 3),
            Err(TrySendError::Closed(3))
        ));
        assert!(!clock.is_at_cap());
        assert_eq!(rx.try_recv(), Ok(1), "buffered work still drains");
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
        assert!(!clock.is_at_cap());
    }

    #[tokio::test]
    async fn losing_the_receiver_while_full_stops_the_clock() {
        let clock = metrics::CapClock::new();
        let observer = QueueObserver::new(&clock);
        let (tx, rx) = mpsc::channel(1);
        let rx = observer.receiver(rx);
        observer.send(&tx, 1).await.expect("last slot");
        assert!(observer.admit(&tx));
        assert!(clock.is_at_cap());
        drop(rx);
        assert!(tx.is_closed());
        assert!(!clock.is_at_cap());
        assert!(observer.send(&tx, 2).await.is_err());
        assert!(!clock.is_at_cap());
    }

    #[tokio::test]
    async fn concurrent_sends_and_receives_leave_an_empty_queue_off_the_cap() {
        let clock = metrics::CapClock::new();
        let observer = QueueObserver::new(&clock);
        let (tx, rx) = mpsc::channel(2);
        let mut rx = observer.receiver(rx);
        let mut batch = Vec::new();
        tokio::join!(
            async {
                for value in 0..100 {
                    observer.admit(&tx);
                    observer.send(&tx, value).await.expect("receiver alive");
                }
            },
            async {
                while batch.len() < 100 {
                    assert!(rx.recv_many(&mut batch, 2).await > 0);
                }
            }
        );
        assert_eq!(batch, (0..100).collect::<Vec<_>>());
        assert_eq!(tx.capacity(), 2);
        assert!(!clock.is_at_cap());
    }
}
