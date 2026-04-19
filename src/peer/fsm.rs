//! BGP peer finite state machine (RFC 4271 §8).
//!
//! Implemented as a pure `(state, event) -> (state', actions)`
//! function so it can be exhaustively unit-tested without touching
//! a socket or a clock. The driver loop in [`super::Peer`]
//! translates real I/O and timer events into [`PeerEvent`]s and
//! executes the [`Action`]s the FSM emits.
//!
//! ## State diagram (v1 simplified)
//!
//! ```text
//!                       +--------+
//!         AutomaticStop |        | AutomaticStart
//!         <-------------+  Idle  +-------------->
//!                       |        |
//!                       +--------+
//!                            |
//!                            v
//!                       +--------+
//!                       |        |
//!                       | Connect|<-+ ConnectRetryTimer
//!                       |        |  |
//!                       +---+----+  |
//!                           |       |
//!         TcpFails          |       |
//!         +-----------------+       |
//!         |                 |       |
//!         |                 v       |
//!         |            +--------+   |
//!         |            |        +---+
//!         +----------->| Active |
//!                      |        |
//!                      +---+----+
//!                          | TcpConnected
//!                          v
//!                     +----------+
//!                     |          |
//!                     | OpenSent |
//!                     |          |
//!                     +----+-----+
//!                          | OpenReceived (compatible)
//!                          v
//!                     +-----------+
//!                     |           |
//!                     |OpenConfirm|
//!                     |           |
//!                     +-----+-----+
//!                           | KeepAliveReceived
//!                           v
//!                     +-----------+
//!                     |           |
//!                     |Established|
//!                     |           |
//!                     +-----------+
//! ```
//!
//! The full RFC FSM has more events (DelayOpen, collision
//! detection, IdleHoldTimer, etc.). v1 implements the happy-path
//! progression plus error transitions back to Idle. Collision
//! detection lives in v2 once we have peers that initiate from
//! both sides simultaneously.

use std::time::Duration;

use crate::error::ErrorCode;
use crate::packet::open::Open;
use crate::packet::update::Update;

/// Peer FSM state per RFC 4271 §8.2.1 (v1 simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

/// Static configuration the FSM needs to construct outgoing
/// messages and validate incoming ones.
#[derive(Debug, Clone)]
pub struct PeerFsmConfig {
    pub local_asn: u32,
    pub local_router_id: std::net::Ipv4Addr,
    pub remote_asn: u32,
    pub local_hold_time: u16,
    pub connect_retry: Duration,
}

impl Default for PeerFsmConfig {
    fn default() -> Self {
        PeerFsmConfig {
            local_asn: 0,
            local_router_id: std::net::Ipv4Addr::UNSPECIFIED,
            remote_asn: 0,
            local_hold_time: 90,
            connect_retry: Duration::from_secs(120),
        }
    }
}

/// Events fed into the FSM by the driver loop.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// Operator (or systemd) wants the session to come up.
    Start,
    /// Operator wants the session torn down.
    Stop,
    /// Underlying TCP `connect()` succeeded.
    TcpConnected,
    /// Underlying TCP `connect()` failed or socket dropped.
    TcpFails,
    /// ConnectRetryTimer expired.
    ConnectRetryTimerExpires,
    /// HoldTimer expired (no traffic from peer for `hold_time` s).
    HoldTimerExpires,
    /// KeepaliveTimer expired (time to send our own KEEPALIVE).
    KeepaliveTimerExpires,
    /// Decoded a valid OPEN from the peer.
    OpenReceived(Open),
    /// Decoded a valid KEEPALIVE.
    KeepaliveReceived,
    /// Decoded a valid UPDATE. The driver passes it along; the
    /// FSM only resets the HoldTimer and forwards via
    /// [`Action::DeliverUpdate`].
    UpdateReceived(Update),
    /// Peer sent us a NOTIFICATION; tear down.
    NotificationReceived { code: ErrorCode, subcode: u8 },
    /// Codec-side parse failure on an inbound message. The driver
    /// has already classified the action; we just fold it into the
    /// FSM as a fatal error for v1 (treat-as-withdraw is handled
    /// at the UPDATE layer once the FSM hands the message off).
    MessageParseError,
}

/// Side-effect requests emitted by the FSM. The driver loop
/// translates these into actual I/O / timer manipulations.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Open a TCP connection to the peer.
    InitiateTcpConnect,
    /// Drop the TCP connection.
    DropTcpConnect,
    /// Send an OPEN message we just constructed.
    SendOpen(Open),
    /// Send a KEEPALIVE.
    SendKeepalive,
    /// Send a NOTIFICATION with this code/subcode (and an empty
    /// data field — v1 doesn't include diagnostic data yet).
    SendNotification { code: ErrorCode, subcode: u8 },
    /// Hand a freshly-parsed UPDATE off to the Adj-RIB-In layer.
    /// Only emitted from the Established state.
    DeliverUpdate(Update),
    /// Restart (or arm) the named timer with a new duration.
    ArmTimer { kind: TimerKind, after: Duration },
    /// Cancel the named timer.
    CancelTimer { kind: TimerKind },
    /// Cancel everything — used when transitioning back to Idle.
    CancelAllTimers,
    /// Mark the session up (driver opens the ribd session,
    /// kicks off the rib-push thread, etc.).
    SessionEstablished,
}

// Re-export so tests and the driver can refer to the same enum.
pub use super::timers::TimerKind;

/// The FSM. Owns its current state and its config; the driver
/// owns timers and the transport.
#[derive(Debug)]
pub struct Fsm {
    pub state: PeerState,
    pub config: PeerFsmConfig,
    /// Negotiated hold time after a successful OPEN exchange.
    /// `min(local_hold_time, peer_hold_time)`. Zero disables
    /// keepalives entirely (RFC 4271 §4.4).
    pub negotiated_hold_time: u16,
}

impl Fsm {
    pub fn new(config: PeerFsmConfig) -> Self {
        Fsm {
            state: PeerState::Idle,
            config,
            negotiated_hold_time: 0,
        }
    }

    /// Handle one event. Returns the actions the driver should
    /// execute. Pure: state mutation only happens through this
    /// function so behavioral tests can drive the whole machine
    /// without any clocks or sockets.
    pub fn handle_event(&mut self, event: PeerEvent) -> Vec<Action> {
        match (self.state, event) {
            // ---- Idle ----
            (PeerState::Idle, PeerEvent::Start) => {
                self.state = PeerState::Connect;
                vec![
                    Action::InitiateTcpConnect,
                    Action::ArmTimer {
                        kind: TimerKind::ConnectRetry,
                        after: self.config.connect_retry,
                    },
                ]
            }
            (PeerState::Idle, _) => Vec::new(),

            // ---- Connect ----
            (PeerState::Connect, PeerEvent::TcpConnected) => {
                self.state = PeerState::OpenSent;
                let open = self.build_open();
                let actions = vec![
                    Action::CancelTimer {
                        kind: TimerKind::ConnectRetry,
                    },
                    Action::SendOpen(open),
                    Action::ArmTimer {
                        kind: TimerKind::Hold,
                        // RFC 4271 §8.2.2: the initial hold timer
                        // before a successful OPEN exchange is
                        // "large", per recommendation 4 minutes.
                        after: Duration::from_secs(240),
                    },
                ]
                ;
                actions
            }
            (PeerState::Connect, PeerEvent::TcpFails) => {
                self.state = PeerState::Active;
                vec![Action::ArmTimer {
                    kind: TimerKind::ConnectRetry,
                    after: self.config.connect_retry,
                }]
            }
            (PeerState::Connect, PeerEvent::ConnectRetryTimerExpires) => {
                vec![
                    Action::DropTcpConnect,
                    Action::InitiateTcpConnect,
                    Action::ArmTimer {
                        kind: TimerKind::ConnectRetry,
                        after: self.config.connect_retry,
                    },
                ]
            }
            (PeerState::Connect, PeerEvent::Stop) => self.go_idle(),
            (PeerState::Connect, _) => Vec::new(),

            // ---- Active ----
            (PeerState::Active, PeerEvent::ConnectRetryTimerExpires) => {
                self.state = PeerState::Connect;
                vec![
                    Action::InitiateTcpConnect,
                    Action::ArmTimer {
                        kind: TimerKind::ConnectRetry,
                        after: self.config.connect_retry,
                    },
                ]
            }
            (PeerState::Active, PeerEvent::TcpConnected) => {
                // Passive side of a collision-free session. Same
                // transition as Connect → OpenSent.
                self.state = PeerState::OpenSent;
                let open = self.build_open();
                vec![
                    Action::CancelTimer {
                        kind: TimerKind::ConnectRetry,
                    },
                    Action::SendOpen(open),
                    Action::ArmTimer {
                        kind: TimerKind::Hold,
                        after: Duration::from_secs(240),
                    },
                ]
            }
            (PeerState::Active, PeerEvent::Stop) => self.go_idle(),
            (PeerState::Active, _) => Vec::new(),

            // ---- OpenSent ----
            (PeerState::OpenSent, PeerEvent::OpenReceived(open)) => {
                if open.asn != self.config.remote_asn {
                    return self.notify_and_idle(
                        ErrorCode::OpenMessage,
                        crate::error::OpenMessageSubcode::BadPeerAs as u8,
                    );
                }
                if open.hold_time > 0 && open.hold_time < 3 {
                    // RFC 4271 §4.2: hold time must be 0 or >= 3.
                    return self.notify_and_idle(
                        ErrorCode::OpenMessage,
                        crate::error::OpenMessageSubcode::UnacceptableHoldTime as u8,
                    );
                }
                self.negotiated_hold_time =
                    self.config.local_hold_time.min(open.hold_time);
                self.state = PeerState::OpenConfirm;
                let mut actions = vec![Action::SendKeepalive];
                if self.negotiated_hold_time > 0 {
                    actions.push(Action::ArmTimer {
                        kind: TimerKind::Hold,
                        after: Duration::from_secs(self.negotiated_hold_time as u64),
                    });
                    actions.push(Action::ArmTimer {
                        kind: TimerKind::Keepalive,
                        after: Duration::from_secs(
                            (self.negotiated_hold_time / 3) as u64,
                        ),
                    });
                } else {
                    // RFC 4271 §4.4: hold = 0 disables both timers.
                    actions.push(Action::CancelTimer { kind: TimerKind::Hold });
                    actions.push(Action::CancelTimer { kind: TimerKind::Keepalive });
                }
                actions
            }
            (PeerState::OpenSent, PeerEvent::HoldTimerExpires) => {
                self.notify_and_idle(ErrorCode::HoldTimerExpired, 0)
            }
            (PeerState::OpenSent, PeerEvent::TcpFails) => {
                self.state = PeerState::Active;
                vec![Action::ArmTimer {
                    kind: TimerKind::ConnectRetry,
                    after: self.config.connect_retry,
                }]
            }
            (PeerState::OpenSent, PeerEvent::Stop) => self.go_idle(),
            (PeerState::OpenSent, PeerEvent::NotificationReceived { .. }) => self.go_idle(),
            // A late `Start` from the instance layer's auto-retry
            // path is harmless — the session is already coming
            // up. Drop it silently rather than treat it as an
            // FSM error and tear down the session.
            (PeerState::OpenSent, PeerEvent::Start) => Vec::new(),
            (PeerState::OpenSent, _) => self.notify_and_idle(ErrorCode::FsmError, 0),

            // ---- OpenConfirm ----
            (PeerState::OpenConfirm, PeerEvent::KeepaliveReceived) => {
                self.state = PeerState::Established;
                let mut actions = vec![Action::SessionEstablished];
                if self.negotiated_hold_time > 0 {
                    actions.push(Action::ArmTimer {
                        kind: TimerKind::Hold,
                        after: Duration::from_secs(self.negotiated_hold_time as u64),
                    });
                }
                actions
            }
            (PeerState::OpenConfirm, PeerEvent::KeepaliveTimerExpires) => {
                let mut actions = vec![Action::SendKeepalive];
                if self.negotiated_hold_time > 0 {
                    actions.push(Action::ArmTimer {
                        kind: TimerKind::Keepalive,
                        after: Duration::from_secs(
                            (self.negotiated_hold_time / 3) as u64,
                        ),
                    });
                }
                actions
            }
            (PeerState::OpenConfirm, PeerEvent::HoldTimerExpires) => {
                self.notify_and_idle(ErrorCode::HoldTimerExpired, 0)
            }
            (PeerState::OpenConfirm, PeerEvent::TcpFails)
            | (PeerState::OpenConfirm, PeerEvent::Stop) => self.go_idle(),
            (PeerState::OpenConfirm, PeerEvent::NotificationReceived { .. }) => {
                self.go_idle()
            }
            // Same rationale as OpenSent: late retry is harmless.
            (PeerState::OpenConfirm, PeerEvent::Start) => Vec::new(),
            (PeerState::OpenConfirm, _) => self.notify_and_idle(ErrorCode::FsmError, 0),

            // ---- Established ----
            (PeerState::Established, PeerEvent::KeepaliveReceived) => {
                if self.negotiated_hold_time > 0 {
                    vec![Action::ArmTimer {
                        kind: TimerKind::Hold,
                        after: Duration::from_secs(self.negotiated_hold_time as u64),
                    }]
                } else {
                    Vec::new()
                }
            }
            (PeerState::Established, PeerEvent::UpdateReceived(update)) => {
                let mut actions = Vec::new();
                if self.negotiated_hold_time > 0 {
                    actions.push(Action::ArmTimer {
                        kind: TimerKind::Hold,
                        after: Duration::from_secs(self.negotiated_hold_time as u64),
                    });
                }
                actions.push(Action::DeliverUpdate(update));
                actions
            }
            (PeerState::Established, PeerEvent::KeepaliveTimerExpires) => {
                let mut actions = vec![Action::SendKeepalive];
                if self.negotiated_hold_time > 0 {
                    actions.push(Action::ArmTimer {
                        kind: TimerKind::Keepalive,
                        after: Duration::from_secs(
                            (self.negotiated_hold_time / 3) as u64,
                        ),
                    });
                }
                actions
            }
            (PeerState::Established, PeerEvent::HoldTimerExpires) => {
                self.notify_and_idle(ErrorCode::HoldTimerExpired, 0)
            }
            (PeerState::Established, PeerEvent::TcpFails)
            | (PeerState::Established, PeerEvent::Stop) => self.go_idle(),
            (PeerState::Established, PeerEvent::NotificationReceived { .. }) => {
                self.go_idle()
            }
            (PeerState::Established, _) => Vec::new(),
        }
    }

    fn build_open(&self) -> Open {
        Open::new(
            self.config.local_asn,
            self.config.local_hold_time,
            self.config.local_router_id,
            vec![
                crate::packet::caps::Capability::Multiprotocol {
                    afi: crate::packet::caps::AFI_IPV4,
                    safi: crate::packet::caps::SAFI_UNICAST,
                },
                crate::packet::caps::Capability::Multiprotocol {
                    afi: crate::packet::caps::AFI_IPV6,
                    safi: crate::packet::caps::SAFI_UNICAST,
                },
                crate::packet::caps::Capability::RouteRefresh,
            ],
        )
    }

    fn go_idle(&mut self) -> Vec<Action> {
        self.state = PeerState::Idle;
        self.negotiated_hold_time = 0;
        vec![Action::DropTcpConnect, Action::CancelAllTimers]
    }

    fn notify_and_idle(&mut self, code: ErrorCode, subcode: u8) -> Vec<Action> {
        self.state = PeerState::Idle;
        self.negotiated_hold_time = 0;
        vec![
            Action::SendNotification { code, subcode },
            Action::DropTcpConnect,
            Action::CancelAllTimers,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::caps::Capability;
    use std::net::Ipv4Addr;

    fn config() -> PeerFsmConfig {
        PeerFsmConfig {
            local_asn: 65000,
            local_router_id: Ipv4Addr::new(10, 0, 0, 1),
            remote_asn: 65001,
            local_hold_time: 90,
            connect_retry: Duration::from_secs(120),
        }
    }

    fn peer_open(asn: u32, hold: u16) -> Open {
        Open::new(
            asn,
            hold,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![Capability::Multiprotocol {
                afi: crate::packet::caps::AFI_IPV4,
                safi: crate::packet::caps::SAFI_UNICAST,
            }],
        )
    }

    #[test]
    fn idle_to_connect_on_start() {
        let mut fsm = Fsm::new(config());
        let actions = fsm.handle_event(PeerEvent::Start);
        assert_eq!(fsm.state, PeerState::Connect);
        // Must initiate TCP and arm ConnectRetry.
        assert!(matches!(actions[0], Action::InitiateTcpConnect));
        assert!(matches!(
            actions[1],
            Action::ArmTimer {
                kind: TimerKind::ConnectRetry,
                ..
            }
        ));
    }

    #[test]
    fn connect_to_open_sent_on_tcp_connected() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        let actions = fsm.handle_event(PeerEvent::TcpConnected);
        assert_eq!(fsm.state, PeerState::OpenSent);
        // Must cancel ConnectRetry and send OPEN.
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer { kind: TimerKind::ConnectRetry })));
        assert!(actions.iter().any(|a| matches!(a, Action::SendOpen(_))));
    }

    #[test]
    fn connect_to_active_on_tcp_failure() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpFails);
        assert_eq!(fsm.state, PeerState::Active);
    }

    #[test]
    fn active_back_to_connect_on_retry_timer() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpFails);
        let actions = fsm.handle_event(PeerEvent::ConnectRetryTimerExpires);
        assert_eq!(fsm.state, PeerState::Connect);
        assert!(actions.iter().any(|a| matches!(a, Action::InitiateTcpConnect)));
    }

    #[test]
    fn open_sent_to_open_confirm_on_valid_open() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        let actions = fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 90)));
        assert_eq!(fsm.state, PeerState::OpenConfirm);
        assert_eq!(fsm.negotiated_hold_time, 90);
        assert!(actions.iter().any(|a| matches!(a, Action::SendKeepalive)));
        // Both Hold and Keepalive timers armed.
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ArmTimer { kind: TimerKind::Hold, .. })));
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::ArmTimer { kind: TimerKind::Keepalive, .. }
        )));
    }

    #[test]
    fn hold_time_negotiated_to_minimum() {
        let mut fsm = Fsm::new(PeerFsmConfig {
            local_hold_time: 30,
            ..config()
        });
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        // Peer offers 60; we offered 30; minimum is 30.
        fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 60)));
        assert_eq!(fsm.negotiated_hold_time, 30);
    }

    #[test]
    fn hold_time_zero_disables_timers() {
        let mut fsm = Fsm::new(PeerFsmConfig {
            local_hold_time: 0,
            ..config()
        });
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        let actions = fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 0)));
        assert_eq!(fsm.negotiated_hold_time, 0);
        // Hold and Keepalive should be CancelTimer, not ArmTimer.
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer { kind: TimerKind::Hold })));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer { kind: TimerKind::Keepalive })));
    }

    #[test]
    fn open_with_wrong_asn_sends_notification() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        let actions = fsm.handle_event(PeerEvent::OpenReceived(peer_open(99999, 90)));
        assert_eq!(fsm.state, PeerState::Idle);
        let notif = actions.iter().find_map(|a| match a {
            Action::SendNotification { code, subcode } => Some((*code, *subcode)),
            _ => None,
        });
        let (code, subcode) = notif.unwrap();
        assert_eq!(code, ErrorCode::OpenMessage);
        assert_eq!(
            subcode,
            crate::error::OpenMessageSubcode::BadPeerAs as u8
        );
    }

    #[test]
    fn open_confirm_to_established_on_keepalive() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 90)));
        let actions = fsm.handle_event(PeerEvent::KeepaliveReceived);
        assert_eq!(fsm.state, PeerState::Established);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SessionEstablished)));
    }

    #[test]
    fn established_keepalive_received_resets_hold_only() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 90)));
        fsm.handle_event(PeerEvent::KeepaliveReceived);
        let actions = fsm.handle_event(PeerEvent::KeepaliveReceived);
        assert_eq!(fsm.state, PeerState::Established);
        // Just rearms hold; doesn't send anything.
        assert!(actions
            .iter()
            .all(|a| matches!(a, Action::ArmTimer { kind: TimerKind::Hold, .. })));
    }

    #[test]
    fn established_keepalive_timer_sends_and_rearms() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 90)));
        fsm.handle_event(PeerEvent::KeepaliveReceived);
        let actions = fsm.handle_event(PeerEvent::KeepaliveTimerExpires);
        assert!(actions.iter().any(|a| matches!(a, Action::SendKeepalive)));
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::ArmTimer { kind: TimerKind::Keepalive, .. }
        )));
    }

    #[test]
    fn established_hold_timer_expires_notifies_and_idles() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 90)));
        fsm.handle_event(PeerEvent::KeepaliveReceived);
        let actions = fsm.handle_event(PeerEvent::HoldTimerExpires);
        assert_eq!(fsm.state, PeerState::Idle);
        let notif = actions.iter().find_map(|a| match a {
            Action::SendNotification { code, subcode } => Some((*code, *subcode)),
            _ => None,
        });
        let (code, _) = notif.unwrap();
        assert_eq!(code, ErrorCode::HoldTimerExpired);
    }

    #[test]
    fn established_update_received_delivers_and_resets_hold() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 90)));
        fsm.handle_event(PeerEvent::KeepaliveReceived);
        let actions =
            fsm.handle_event(PeerEvent::UpdateReceived(Update::empty()));
        assert!(actions.iter().any(|a| matches!(a, Action::DeliverUpdate(_))));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ArmTimer { kind: TimerKind::Hold, .. })));
    }

    #[test]
    fn stop_from_any_state_returns_to_idle() {
        for start_state in [
            PeerState::Connect,
            PeerState::Active,
            PeerState::OpenSent,
            PeerState::OpenConfirm,
            PeerState::Established,
        ] {
            let mut fsm = Fsm::new(config());
            // Drive to the test state via the happy path, then jam
            // it directly (cheaper than scripting every transition).
            fsm.state = start_state;
            fsm.handle_event(PeerEvent::Stop);
            assert_eq!(
                fsm.state,
                PeerState::Idle,
                "Stop from {:?} should land in Idle",
                start_state
            );
        }
    }

    #[test]
    fn established_tcp_fails_returns_to_idle() {
        let mut fsm = Fsm::new(config());
        fsm.state = PeerState::Established;
        fsm.handle_event(PeerEvent::TcpFails);
        assert_eq!(fsm.state, PeerState::Idle);
    }

    #[test]
    fn start_in_non_idle_states_is_noop() {
        // The instance layer auto-retries dropped sessions by
        // sending `Start` after a backoff. If the peer has
        // already come back up by the time the retry lands, the
        // FSM must treat it as a no-op rather than an FSM error.
        // This test pins that contract for every non-Idle state.
        for state in [
            PeerState::Connect,
            PeerState::Active,
            PeerState::OpenSent,
            PeerState::OpenConfirm,
            PeerState::Established,
        ] {
            let mut fsm = Fsm::new(config());
            fsm.state = state;
            let actions = fsm.handle_event(PeerEvent::Start);
            assert_eq!(
                fsm.state, state,
                "Start must not change state from {:?}",
                state
            );
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, Action::SendNotification { .. })),
                "Start must not emit NOTIFICATION from {:?}, got {:?}",
                state,
                actions
            );
        }
    }

    #[test]
    fn open_with_unacceptable_hold_time_notifies() {
        let mut fsm = Fsm::new(config());
        fsm.handle_event(PeerEvent::Start);
        fsm.handle_event(PeerEvent::TcpConnected);
        // Hold = 1 is not allowed (must be 0 or >= 3).
        let actions =
            fsm.handle_event(PeerEvent::OpenReceived(peer_open(65001, 1)));
        let notif = actions.iter().find_map(|a| match a {
            Action::SendNotification { code, subcode } => Some((*code, *subcode)),
            _ => None,
        });
        let (code, subcode) = notif.unwrap();
        assert_eq!(code, ErrorCode::OpenMessage);
        assert_eq!(
            subcode,
            crate::error::OpenMessageSubcode::UnacceptableHoldTime as u8
        );
        assert_eq!(fsm.state, PeerState::Idle);
    }
}
