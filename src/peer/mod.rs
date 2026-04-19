//! Per-peer state and driver loop.
//!
//! The driver pattern is:
//!
//! ```text
//!          ┌─────────────────────────────────────────────┐
//!          │              Peer::run() loop               │
//!          │                                             │
//!          │  select! {                                  │
//!          │    msg = transport.recv_message() => {      │
//!          │       decode → PeerEvent::*Received         │
//!          │    }                                        │
//!          │    _ = sleep_until(timers.next_deadline) => │
//!          │       PeerEvent::*TimerExpires              │
//!          │    cmd = control_rx.recv() => {             │
//!          │       PeerEvent::Start | Stop               │
//!          │    }                                        │
//!          │  }                                          │
//!          │                                             │
//!          │  for action in fsm.handle_event(event) {    │
//!          │     execute(action)                         │
//!          │  }                                          │
//!          └─────────────────────────────────────────────┘
//! ```
//!
//! The FSM is pure logic (see [`fsm`]). The timers are pure state
//! (see [`timers`]). The transport is async I/O (see
//! [`transport`]). The driver loop is the only async bit; it holds
//! all three and translates between the synchronous FSM world and
//! the async network world.
//!
//! This module ships a usable Peer driver but does NOT yet wire it
//! into a top-level `BgpInstance`. That's B5 (rib-push) and B6
//! (control socket) territory.

pub mod fsm;
pub mod timers;
pub mod transport;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::sleep_until;

use crate::packet::header::{Header, MessageType};
use crate::packet::notification::Notification;
use crate::packet::{keepalive, open::Open, update::Update};

use fsm::{Action, Fsm, PeerEvent, PeerFsmConfig, PeerState};
use timers::{TimerKind, Timers};
use transport::{BgpTransport, TokioTcpTransport, TransportError};

/// Connection parameters the driver needs to actually open a TCP
/// session when the FSM dispatches `InitiateTcpConnect`. Built
/// from `BgpPeerConfig` by the instance layer and handed to the
/// Peer constructor. Tests can leave this as `None` and inject
/// transports directly via [`Peer::set_transport`].
#[derive(Debug, Clone)]
pub struct PeerConnectInfo {
    pub peer: SocketAddr,
    pub source: Option<SocketAddr>,
    pub password: Option<String>,
    pub timeout: Duration,
}

/// Top-level per-peer driver.
///
/// Owns a single peer's FSM, timers, and transport. Spawned as one
/// tokio task per configured peer by [`crate::instance::BgpInstance`]
/// (which doesn't exist yet — B4/B5 fill that in). For now the
/// driver is exercised directly by the integration tests that
/// stand up a fake peer.
pub struct Peer {
    fsm: Fsm,
    timers: Timers,
    transport: Option<Box<dyn BgpTransport>>,
    /// Channel used by the parent task to issue control commands
    /// (Start, Stop, ConfigUpdate, etc.).
    control_rx: mpsc::Receiver<PeerControl>,
    /// Channel used by the driver to publish state changes back
    /// to the parent. Used by the query path.
    state_tx: mpsc::Sender<PeerStateUpdate>,
    /// Connection parameters used by `Action::InitiateTcpConnect`.
    /// `None` in test mode where the transport is injected.
    connect_info: Option<PeerConnectInfo>,
    /// When set, the peer uses VPP's VCL TCP stack instead of
    /// kernel TCP. Initialized by the instance layer when the
    /// daemon is configured for VCL mode.
    #[cfg(feature = "vcl")]
    vcl_reactor: Option<vcl_rs::VclReactor>,
}

/// Control commands the parent task can send to the driver loop.
pub enum PeerControl {
    Start,
    Stop,
    /// Send a fully-constructed UPDATE on the wire. The driver
    /// drops it on the floor with a warning if the peer isn't
    /// currently in `Established`. Used by the instance layer to
    /// push initial bulk advertisements on session-up and any
    /// future incremental updates. The FSM is not consulted —
    /// "while in Established, send these bytes" doesn't need a
    /// state-machine event; bypassing the FSM keeps it pure.
    SendUpdate(Update),
    /// Read the local end of the active TCP socket. Used by the
    /// instance layer to learn the BGP next-hop ("next-hop self"
    /// for iBGP) so it can construct outbound UPDATEs whose
    /// NEXT_HOP attribute / MP_REACH NEXT_HOP carry the right
    /// address. The reply comes back via the supplied oneshot.
    QueryLocalAddr(tokio::sync::oneshot::Sender<Option<std::net::SocketAddr>>),
    /// Inject a pre-connected transport from the listener (passive
    /// open). The peer driver sets the transport, fires
    /// TcpConnected on the FSM, and proceeds as if it had connected
    /// itself. Used by the instance's listener task when an inbound
    /// connection from a known peer arrives.
    InjectTransport(Box<dyn BgpTransport>),
}

/// State updates the driver task publishes to the parent.
#[derive(Debug, Clone)]
pub enum PeerStateUpdate {
    StateChanged(PeerState),
    SessionEstablished,
    UpdateReceived(Update),
}

/// Outcome of a single driver-loop iteration. Returned by
/// [`Peer::step`] so the run loop can decide whether to keep
/// going or shut down.
#[derive(Debug, PartialEq, Eq)]
enum StepOutcome {
    Continue,
    Stopped,
}

impl Peer {
    /// Create a Peer with an explicit FSM config and the channels
    /// it'll use to talk to its parent task. The Peer starts in
    /// Idle; send a `PeerControl::Start` to bring it up.
    pub fn new(
        config: PeerFsmConfig,
        control_rx: mpsc::Receiver<PeerControl>,
        state_tx: mpsc::Sender<PeerStateUpdate>,
    ) -> Self {
        Peer {
            fsm: Fsm::new(config),
            timers: Timers::new(),
            transport: None,
            control_rx,
            state_tx,
            connect_info: None,
            #[cfg(feature = "vcl")]
            vcl_reactor: None,
        }
    }

    /// Set the connect info used by the driver when the FSM
    /// dispatches `Action::InitiateTcpConnect`. The instance
    /// layer calls this once after constructing the Peer.
    pub fn set_connect_info(&mut self, info: PeerConnectInfo) {
        self.connect_info = Some(info);
    }

    #[cfg(feature = "vcl")]
    pub fn set_vcl_reactor(&mut self, reactor: vcl_rs::VclReactor) {
        self.vcl_reactor = Some(reactor);
    }

    pub fn state(&self) -> PeerState {
        self.fsm.state
    }

    /// Run the driver loop until a `PeerControl::Stop` arrives or
    /// the control channel closes. This is the main entry point
    /// when a peer task is spawned.
    pub async fn run(mut self) {
        loop {
            match self.step().await {
                StepOutcome::Continue => continue,
                StepOutcome::Stopped => break,
            }
        }
    }

    /// Run one iteration of the driver loop. Public for unit tests
    /// that want to drive the peer step-by-step.
    async fn step(&mut self) -> StepOutcome {
        // Decide what we're waiting on: incoming message, expired
        // timer, or control command. If the transport is None
        // (Idle/Active), we can't recv — skip that branch.
        let next_deadline = self.timers.next_deadline();

        tokio::select! {
            biased;

            // 1. Control commands always take priority so a Stop
            //    can interrupt anything.
            cmd = self.control_rx.recv() => {
                match cmd {
                    Some(PeerControl::Start) => {
                        self.dispatch(PeerEvent::Start).await;
                        StepOutcome::Continue
                    }
                    Some(PeerControl::Stop) => {
                        self.dispatch(PeerEvent::Stop).await;
                        StepOutcome::Stopped
                    }
                    Some(PeerControl::SendUpdate(update)) => {
                        self.send_update_now(update).await;
                        StepOutcome::Continue
                    }
                    Some(PeerControl::QueryLocalAddr(reply)) => {
                        let addr = self
                            .transport
                            .as_ref()
                            .and_then(|t| t.local_addr());
                        let _ = reply.send(addr);
                        StepOutcome::Continue
                    }
                    Some(PeerControl::InjectTransport(transport)) => {
                        // Passive open: the listener accepted a
                        // connection from this peer's address. Close
                        // any existing transport (collision — we
                        // prefer the inbound connection) and inject
                        // the new one.
                        if let Some(mut old) = self.transport.take() {
                            let _ = old.close().await;
                        }
                        // Move FSM to Connect if it's in Idle so
                        // TcpConnected is accepted. We set the state
                        // directly rather than dispatching Start
                        // (which would trigger an outbound connect).
                        if self.fsm.state == PeerState::Idle {
                            self.fsm.state = PeerState::Connect;
                        }
                        self.transport = Some(transport);
                        self.dispatch(PeerEvent::TcpConnected).await;
                        StepOutcome::Continue
                    }
                    None => StepOutcome::Stopped,
                }
            }

            // 2. Timers. Skipped when next_deadline is None.
            _ = async {
                if let Some(d) = next_deadline {
                    sleep_until(d.into()).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                let now = Instant::now();
                let expired = self.timers.expired_at(now);
                for kind in expired {
                    let event = match kind {
                        TimerKind::ConnectRetry => PeerEvent::ConnectRetryTimerExpires,
                        TimerKind::Hold => PeerEvent::HoldTimerExpires,
                        TimerKind::Keepalive => PeerEvent::KeepaliveTimerExpires,
                    };
                    self.dispatch(event).await;
                }
                StepOutcome::Continue
            }

            // 3. Inbound BGP message — only when the transport is
            //    active. We short-circuit when transport is None
            //    by waiting forever in that branch.
            msg = async {
                match self.transport.as_mut() {
                    Some(t) => Some(t.recv_message().await),
                    None => {
                        std::future::pending::<()>().await;
                        None
                    }
                }
            } => {
                let result = match msg {
                    Some(r) => r,
                    None => return StepOutcome::Continue,
                };
                match result {
                    Ok(bytes) => {
                        self.handle_inbound(bytes).await;
                    }
                    Err(TransportError::Closed) => {
                        tracing::debug!(state = ?self.fsm.state, "peer closed connection");
                        self.dispatch(PeerEvent::TcpFails).await;
                    }
                    Err(e) => {
                        tracing::warn!(?e, "transport error; treating as TcpFails");
                        self.dispatch(PeerEvent::TcpFails).await;
                    }
                }
                StepOutcome::Continue
            }
        }
    }

    async fn handle_inbound(&mut self, bytes: Vec<u8>) {
        let header = match Header::parse(&bytes) {
            Ok(h) => h,
            Err(_) => {
                self.dispatch(PeerEvent::MessageParseError).await;
                return;
            }
        };
        let body = &bytes[crate::packet::header::HEADER_LEN..];
        match header.msg_type {
            MessageType::Open => match Open::parse_body(body) {
                Ok(open) => self.dispatch(PeerEvent::OpenReceived(open)).await,
                Err(_) => self.dispatch(PeerEvent::MessageParseError).await,
            },
            MessageType::Update => match Update::parse_body(body) {
                Ok(update) => self.dispatch(PeerEvent::UpdateReceived(update)).await,
                Err(_) => self.dispatch(PeerEvent::MessageParseError).await,
            },
            MessageType::Notification => match Notification::parse_body(body) {
                Ok(n) => {
                    self.dispatch(PeerEvent::NotificationReceived {
                        code: n.code,
                        subcode: n.subcode,
                    })
                    .await
                }
                Err(_) => self.dispatch(PeerEvent::MessageParseError).await,
            },
            MessageType::Keepalive => self.dispatch(PeerEvent::KeepaliveReceived).await,
            MessageType::RouteRefresh => {
                // Route Refresh is informational at this layer —
                // the FSM doesn't care, but B5's rib_push will use
                // it to re-send Adj-RIB-Out. v1 just acknowledges
                // by resetting the hold timer (handled by the
                // generic "any traffic" path the next time we get
                // a real message).
                tracing::debug!("RouteRefresh received (handler arrives in B5)");
            }
        }
    }

    /// Dispatch a single event into the FSM, execute the
    /// resulting actions, and recursively dispatch any follow-up
    /// events the actions produce (e.g. `InitiateTcpConnect`
    /// resolves to `TcpConnected` or `TcpFails`). Bounded by the
    /// FSM itself — it can't infinitely produce events.
    async fn dispatch(&mut self, initial: PeerEvent) {
        let prev_state = self.fsm.state;
        let mut queue: VecDeque<PeerEvent> = VecDeque::new();
        queue.push_back(initial);
        while let Some(event) = queue.pop_front() {
            let actions = self.fsm.handle_event(event);
            for action in actions {
                let followups = self.execute(action).await;
                for ev in followups {
                    queue.push_back(ev);
                }
            }
        }
        if self.fsm.state != prev_state {
            let _ = self
                .state_tx
                .send(PeerStateUpdate::StateChanged(self.fsm.state))
                .await;
        }
    }

    /// Execute one FSM `Action`. Returns any follow-up events the
    /// action produces — e.g. `InitiateTcpConnect` returns
    /// `TcpConnected` on success or `TcpFails` on error so the
    /// FSM can transition without the instance layer having to
    /// inject those events from outside.
    async fn execute(&mut self, action: Action) -> Vec<PeerEvent> {
        match action {
            Action::InitiateTcpConnect => {
                let Some(info) = self.connect_info.clone() else {
                    // No connect info — test mode where the
                    // transport is injected via set_transport.
                    // Tests that use this path either pre-populate
                    // the transport before sending Start, or
                    // synthesize TcpConnected directly via
                    // fsm_mut().handle_event(...).
                    tracing::debug!(
                        "InitiateTcpConnect with no connect_info; assuming test mode"
                    );
                    return Vec::new();
                };
                // Use VCL transport when a reactor is configured,
                // otherwise fall back to kernel TCP.
                #[cfg(feature = "vcl")]
                if let Some(reactor) = &self.vcl_reactor {
                    match transport::VclTransport::connect(
                        info.peer,
                        info.source,
                        info.password.as_deref(),
                        info.timeout,
                        reactor.clone(),
                    )
                    .await
                    {
                        Ok(t) => {
                            self.transport = Some(Box::new(t));
                            return vec![PeerEvent::TcpConnected];
                        }
                        Err(e) => {
                            tracing::info!(peer = %info.peer, "VCL connect failed: {}", e);
                            return vec![PeerEvent::TcpFails];
                        }
                    }
                }

                match TokioTcpTransport::connect(
                    info.peer,
                    info.source,
                    info.password.as_deref(),
                    info.timeout,
                )
                .await
                {
                    Ok(t) => {
                        self.transport = Some(Box::new(t));
                        vec![PeerEvent::TcpConnected]
                    }
                    Err(e) => {
                        tracing::info!(peer = %info.peer, "TCP connect failed: {}", e);
                        vec![PeerEvent::TcpFails]
                    }
                }
            }
            Action::DropTcpConnect => {
                if let Some(mut t) = self.transport.take() {
                    let _ = t.close().await;
                }
                Vec::new()
            }
            Action::SendOpen(open) => {
                if let Some(t) = self.transport.as_mut() {
                    let bytes = open.encode();
                    if let Err(e) = t.send_message(&bytes).await {
                        tracing::warn!(?e, "failed to send OPEN");
                    }
                }
                Vec::new()
            }
            Action::SendKeepalive => {
                if let Some(t) = self.transport.as_mut() {
                    if let Err(e) = t.send_message(&keepalive::encode()).await {
                        tracing::warn!(?e, "failed to send KEEPALIVE");
                    }
                }
                Vec::new()
            }
            Action::SendNotification { code, subcode } => {
                if let Some(t) = self.transport.as_mut() {
                    let n = Notification::new(code, subcode, Vec::new());
                    let _ = t.send_message(&n.encode()).await;
                }
                Vec::new()
            }
            Action::DeliverUpdate(update) => {
                let _ = self
                    .state_tx
                    .send(PeerStateUpdate::UpdateReceived(update))
                    .await;
                Vec::new()
            }
            Action::ArmTimer { kind, after } => {
                self.timers.arm(kind, after, Instant::now());
                Vec::new()
            }
            Action::CancelTimer { kind } => {
                self.timers.cancel(kind);
                Vec::new()
            }
            Action::CancelAllTimers => {
                self.timers.cancel_all();
                Vec::new()
            }
            Action::SessionEstablished => {
                let _ = self
                    .state_tx
                    .send(PeerStateUpdate::SessionEstablished)
                    .await;
                Vec::new()
            }
        }
    }

    /// Inject an already-connected transport. Used by the
    /// instance layer (B5) once it has performed the TCP connect
    /// dance, and by the integration tests.
    pub fn set_transport(&mut self, transport: Box<dyn BgpTransport>) {
        self.transport = Some(transport);
    }

    /// Send an UPDATE on the active transport iff the peer is
    /// currently in `Established`. Drops the message with a
    /// warning otherwise — the instance layer is responsible for
    /// scheduling sends only when the session is up. The intent
    /// is to keep this side fail-safe: an UPDATE that arrives
    /// during a session-down race just gets discarded rather
    /// than queuing on a dead channel.
    async fn send_update_now(&mut self, update: Update) {
        if self.fsm.state != PeerState::Established {
            tracing::warn!(
                state = ?self.fsm.state,
                "dropping SendUpdate — peer not Established"
            );
            return;
        }
        let Some(t) = self.transport.as_mut() else {
            tracing::warn!("dropping SendUpdate — no transport");
            return;
        };
        let bytes = update.encode();
        if let Err(e) = t.send_message(&bytes).await {
            tracing::warn!(?e, "send_update transport error");
        }
    }

    /// Test-only access to the inner FSM. The instance layer in
    /// B5 will use this to drive the connect dance from outside
    /// the run loop; integration tests use it to script the FSM
    /// past the InitiateTcpConnect Action (which is a no-op at
    /// the driver level by design — the instance layer owns real
    /// connects).
    pub fn fsm_mut(&mut self) -> &mut Fsm {
        &mut self.fsm
    }

    pub fn timers_mut(&mut self) -> &mut Timers {
        &mut self.timers
    }

    pub fn transport_mut(&mut self) -> &mut Option<Box<dyn BgpTransport>> {
        &mut self.transport
    }
}

// End-to-end driver tests live in `tests/peer_driver.rs` (added
// alongside the wire-format integration tests in B9). The pure
// FSM tests in `fsm.rs` cover all state transitions, and the
// transport tests in `transport.rs` cover real TCP I/O — the
// driver loop is the (small) glue between them.
