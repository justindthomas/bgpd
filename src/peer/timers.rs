//! BGP timers — pure tracking, no async machinery.
//!
//! RFC 4271 §10 defines four mandatory timers:
//!
//! - **ConnectRetryTimer** — how long to wait between TCP connect
//!   attempts. Default 120s; we let configuration override.
//! - **HoldTimer** — how long to wait without seeing a KEEPALIVE
//!   or UPDATE before the peer is considered dead. Negotiated to
//!   `min(local, remote)` in OPEN; v1 default 90s.
//! - **KeepaliveTimer** — how often to send KEEPALIVE. Set to
//!   HoldTime / 3 once the session is Established.
//! - **DelayOpenTimer** — RFC 4271 §8.1.5 optional collision
//!   handling. v1 doesn't implement collision detection (we
//!   either initiate or accept, not both for the same peer), so
//!   this timer is unused.
//!
//! All timers are tracked as `Option<Instant>` deadlines. The
//! driver task polls [`Timers::next_deadline`] to set its tokio
//! sleep, and on wake-up calls [`Timers::expired_at`] with the
//! current time to collect the events to feed into the FSM.

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKind {
    ConnectRetry,
    Hold,
    Keepalive,
}

#[derive(Debug, Default)]
pub struct Timers {
    connect_retry: Option<Instant>,
    hold: Option<Instant>,
    keepalive: Option<Instant>,
}

impl Timers {
    pub fn new() -> Self {
        Timers::default()
    }

    pub fn arm(&mut self, kind: TimerKind, after: Duration, now: Instant) {
        let slot = match kind {
            TimerKind::ConnectRetry => &mut self.connect_retry,
            TimerKind::Hold => &mut self.hold,
            TimerKind::Keepalive => &mut self.keepalive,
        };
        *slot = Some(now + after);
    }

    pub fn cancel(&mut self, kind: TimerKind) {
        let slot = match kind {
            TimerKind::ConnectRetry => &mut self.connect_retry,
            TimerKind::Hold => &mut self.hold,
            TimerKind::Keepalive => &mut self.keepalive,
        };
        *slot = None;
    }

    pub fn cancel_all(&mut self) {
        self.connect_retry = None;
        self.hold = None;
        self.keepalive = None;
    }

    /// Earliest deadline across all armed timers, or `None` if no
    /// timer is currently armed.
    pub fn next_deadline(&self) -> Option<Instant> {
        [self.connect_retry, self.hold, self.keepalive]
            .into_iter()
            .flatten()
            .min()
    }

    /// Return the kinds of timers that have expired by `now`,
    /// clearing them as we go. The caller feeds each one into the
    /// FSM as an event.
    pub fn expired_at(&mut self, now: Instant) -> Vec<TimerKind> {
        let mut out = Vec::new();
        for (slot, kind) in [
            (&mut self.connect_retry, TimerKind::ConnectRetry),
            (&mut self.hold, TimerKind::Hold),
            (&mut self.keepalive, TimerKind::Keepalive),
        ] {
            if let Some(deadline) = *slot {
                if deadline <= now {
                    *slot = None;
                    out.push(kind);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn arm_then_cancel() {
        let mut t = Timers::new();
        let now = t0();
        t.arm(TimerKind::Hold, Duration::from_secs(90), now);
        assert!(t.next_deadline().is_some());
        t.cancel(TimerKind::Hold);
        assert!(t.next_deadline().is_none());
    }

    #[test]
    fn next_deadline_is_min() {
        let mut t = Timers::new();
        let now = t0();
        t.arm(TimerKind::ConnectRetry, Duration::from_secs(120), now);
        t.arm(TimerKind::Hold, Duration::from_secs(90), now);
        t.arm(TimerKind::Keepalive, Duration::from_secs(30), now);
        let next = t.next_deadline().unwrap();
        assert!(next <= now + Duration::from_secs(30));
    }

    #[test]
    fn expired_clears_only_expired_slots() {
        let mut t = Timers::new();
        let now = t0();
        t.arm(TimerKind::Hold, Duration::from_secs(90), now);
        t.arm(TimerKind::Keepalive, Duration::from_secs(30), now);
        // Pretend 31 seconds passed.
        let later = now + Duration::from_secs(31);
        let expired = t.expired_at(later);
        assert_eq!(expired, vec![TimerKind::Keepalive]);
        // Hold is still armed.
        assert!(t.next_deadline().is_some());
        // Calling expired_at again with the same time returns nothing.
        assert!(t.expired_at(later).is_empty());
    }

    #[test]
    fn cancel_all_drops_everything() {
        let mut t = Timers::new();
        let now = t0();
        t.arm(TimerKind::Hold, Duration::from_secs(90), now);
        t.arm(TimerKind::Keepalive, Duration::from_secs(30), now);
        t.cancel_all();
        assert!(t.next_deadline().is_none());
    }
}
