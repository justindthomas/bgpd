//! End-to-end driver loop test: spin up a fake peer over a real
//! localhost TCP connection, hand the bgpd `Peer` an already-
//! connected transport, drive it through the full BGP handshake,
//! and verify it lands in `Established` and delivers an UPDATE
//! through the state channel.
//!
//! Designed to be fast (no waiting on the 90-second hold timer):
//! the fake peer cycles through OPEN → KEEPALIVE → UPDATE → close
//! in well under a second, and we use a short hold time so any
//! timer waits are bounded.

use std::net::Ipv4Addr;
use std::time::Duration;

use bgpd::peer::fsm::{Fsm, PeerEvent, PeerFsmConfig, PeerState};
use bgpd::peer::transport::{BgpTransport, TokioTcpTransport};
use bgpd::peer::{Peer, PeerControl, PeerStateUpdate};
use bgpd::packet::caps::{Capability, AFI_IPV4, SAFI_UNICAST};
use bgpd::packet::header::{Header, HEADER_LEN, MessageType};
use bgpd::packet::keepalive;
use bgpd::packet::open::Open;
use bgpd::packet::update::{Prefix4, Update};
use bgpd::packet::attrs::{AsPathSegment, AsPathSegmentType, Origin, PathAttribute};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

fn local_config() -> PeerFsmConfig {
    PeerFsmConfig {
        local_asn: 65000,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        remote_asn: 65001,
        // Short hold time so the test doesn't sit on a 90-second
        // timer if anything goes sideways.
        local_hold_time: 9,
        connect_retry: Duration::from_secs(120),
    }
}

fn fake_peer_open() -> Open {
    Open::new(
        65001,
        9,
        Ipv4Addr::new(10, 0, 0, 2),
        vec![Capability::Multiprotocol {
            afi: AFI_IPV4,
            safi: SAFI_UNICAST,
        }],
    )
}

fn sample_update() -> Update {
    Update {
        withdrawn_v4: Vec::new(),
        path_attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(vec![AsPathSegment {
                seg_type: AsPathSegmentType::AsSequence,
                asns: vec![65001],
            }]),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        nlri_v4: vec![Prefix4 {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        }],
    }
}

#[tokio::test]
async fn driver_reaches_established_and_delivers_update() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Fake peer task: accept the inbound TCP connection and run
    // the BGP handshake from the other side.
    let fake = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut t = TokioTcpTransport::from_accepted(sock);

        // 1. The driver sends OPEN as soon as TcpConnected fires.
        let bytes = t.recv_message().await.unwrap();
        let h = Header::parse(&bytes).unwrap();
        assert_eq!(h.msg_type, MessageType::Open);
        let _our_view_of_their_open = Open::parse_body(&bytes[HEADER_LEN..]).unwrap();

        // 2. Send our OPEN.
        t.send_message(&fake_peer_open().encode()).await.unwrap();

        // 3. The driver sends KEEPALIVE on receipt of our OPEN
        //    (transitions OpenSent → OpenConfirm).
        let bytes = t.recv_message().await.unwrap();
        assert_eq!(
            Header::parse(&bytes).unwrap().msg_type,
            MessageType::Keepalive
        );

        // 4. Send our KEEPALIVE; the driver transitions
        //    OpenConfirm → Established.
        t.send_message(&keepalive::encode()).await.unwrap();

        // 5. Send an UPDATE — the driver should deliver it via
        //    PeerStateUpdate::UpdateReceived.
        t.send_message(&sample_update().encode()).await.unwrap();

        // Hold the connection open briefly so the driver task has
        // a chance to process everything before we tear down.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = t.close().await;
    });

    // bgpd-side connect.
    let client_transport =
        TokioTcpTransport::connect(addr, None, None, Duration::from_secs(2))
            .await
            .unwrap();

    let (control_tx, control_rx) = mpsc::channel(8);
    let (state_tx, mut state_rx) = mpsc::channel(64);

    // Construct the Peer in Idle, hand it the live transport, and
    // synthesize the FSM up to OpenSent (where the driver loop's
    // recv would naturally take over once we send our OPEN). We
    // bypass the normal Idle → Connect → OpenSent path because
    // the InitiateTcpConnect Action is a no-op in v1 (the
    // instance layer wires the real connect in B5); for the
    // driver loop test we inject a pre-connected transport
    // instead.
    let mut peer = Peer::new(local_config(), control_rx, state_tx);
    peer.set_transport(Box::new(client_transport));
    // Drive the FSM forward via the public test-friendly event
    // path: a synthetic Start (which moves to Connect) then a
    // synthetic TcpConnected. The Action::SendOpen produced by
    // TcpConnected calls back into the transport we just set.
    {
        let actions = peer.fsm_mut().handle_event(PeerEvent::Start);
        // We don't execute InitiateTcpConnect — we already have a
        // live transport. We do execute the ArmTimer for
        // ConnectRetry though, since the driver loop will
        // otherwise fire it later.
        for a in actions {
            if let bgpd::peer::fsm::Action::ArmTimer { kind, after } = a {
                peer.timers_mut().arm(kind, after, std::time::Instant::now());
            }
        }
    }
    {
        let actions = peer.fsm_mut().handle_event(PeerEvent::TcpConnected);
        // Execute the SendOpen action so the fake peer sees our
        // OPEN. ArmTimer / CancelTimer are no-ops for the test.
        for a in actions {
            if let bgpd::peer::fsm::Action::SendOpen(open) = a {
                peer.transport_mut()
                    .as_mut()
                    .unwrap()
                    .send_message(&open.encode())
                    .await
                    .unwrap();
            }
        }
    }

    // Spawn the driver loop now that the FSM is in OpenSent and
    // the OPEN is on the wire.
    let driver = tokio::spawn(async move { peer.run().await });

    // Watch the state channel for SessionEstablished + an UPDATE.
    let mut saw_established = false;
    let mut saw_update = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), state_rx.recv()).await {
            Ok(Some(PeerStateUpdate::SessionEstablished)) => saw_established = true,
            Ok(Some(PeerStateUpdate::UpdateReceived(_))) => saw_update = true,
            Ok(Some(PeerStateUpdate::StateChanged(_))) => {}
            Ok(None) => break,
            Err(_) => {}
        }
        if saw_established && saw_update {
            break;
        }
    }

    let _ = control_tx.send(PeerControl::Stop).await;
    let _ = driver.await;
    let _ = fake.await;

    assert!(saw_established, "peer should reach Established");
    assert!(saw_update, "peer should deliver the UPDATE");
}

// Sanity test for the FSM in isolation (without driver/transport
// wiring) — proves the public API surface from `bgpd::peer`
// is usable by external consumers (which is what the instance
// layer in B5 will need).
#[test]
fn fsm_public_api_is_usable() {
    let mut fsm = Fsm::new(local_config());
    assert_eq!(fsm.state, PeerState::Idle);
    let _ = fsm.handle_event(PeerEvent::Start);
    assert_eq!(fsm.state, PeerState::Connect);
}
