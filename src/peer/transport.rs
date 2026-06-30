//! BGP transport abstraction + Tokio TCP implementation.
//!
//! The `BgpTransport` trait is the interface between the FSM
//! driver loop and the underlying byte stream. v1 ships a single
//! `TokioTcpTransport` implementation that opens an AF_INET /
//! AF_INET6 TCP socket inside the dataplane network namespace
//! (where bgpd already runs via the systemd
//! `JoinsNamespaceOf=netns-dataplane.service` pattern). The trait
//! exists so a future `SmoltcpMemifTransport` can drop in without
//! touching the FSM.
//!
//! ## Framing
//!
//! BGP messages are length-prefixed: the 19-byte header carries a
//! 16-bit length field that includes the header itself, with a
//! valid range of [19, 4096]. [`recv_message`] reads exactly one
//! BGP message at a time and returns the full message bytes
//! (header + body). The caller hands the bytes to the wire codec
//! in [`crate::packet`].
//!
//! ## TCP_MD5SIG
//!
//! RFC 2385 TCP-MD5 is the de-facto standard authentication for
//! production BGP. Linux exposes it via `setsockopt(TCP_MD5SIG)`
//! with a `tcp_md5sig` struct: address family + peer address +
//! key length + zero-padded key. The option MUST be set before
//! `connect()` because it changes the wire format of the SYN
//! handshake itself; setting it on a connected socket has no
//! effect on the in-flight session.
//!
//! Setting TCP_MD5SIG requires `CAP_NET_RAW`. bgpd runs as
//! root inside the dataplane netns via systemd, so we have it.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

use crate::packet::header::{Header, HEADER_LEN, MAX_MESSAGE_LEN};

/// Connection-level errors. Bubbled up to the driver loop, which
/// translates them into [`super::fsm::PeerEvent::TcpFails`].
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("BGP message length {0} out of range [{}, {}]", HEADER_LEN, MAX_MESSAGE_LEN)]
    BadLength(usize),
    #[error("connection closed by peer")]
    Closed,
    #[error("BGP header parse: {0}")]
    Header(String),
}

#[async_trait]
pub trait BgpTransport: Send {
    /// Send a complete BGP message (header + body, already
    /// encoded). Caller is responsible for constructing valid
    /// frames; this method does not validate.
    async fn send_message(&mut self, msg: &[u8]) -> Result<(), TransportError>;

    /// Receive exactly one complete BGP message, blocking until
    /// the full message has arrived. Returns the bytes including
    /// the 19-byte header.
    async fn recv_message(&mut self) -> Result<Vec<u8>, TransportError>;

    /// Close the underlying socket. Idempotent.
    async fn close(&mut self) -> Result<(), TransportError>;

    /// The local address of the connected socket. The instance
    /// layer uses this as the BGP next-hop when constructing
    /// outbound UPDATE messages ("next-hop self" for iBGP).
    /// Returns `None` if the transport isn't currently connected.
    fn local_addr(&self) -> Option<SocketAddr>;
}

#[derive(Debug)]
pub struct TokioTcpTransport {
    stream: Option<TcpStream>,
}

impl TokioTcpTransport {
    /// Connect to `peer` from optional `source` with optional
    /// TCP_MD5SIG. The TCP_MD5SIG password must be set before
    /// connect, so the constructor handles the full
    /// socket-create / setsockopt / bind / connect dance.
    pub async fn connect(
        peer: SocketAddr,
        source: Option<SocketAddr>,
        password: Option<&str>,
        connect_timeout: Duration,
    ) -> Result<Self, TransportError> {
        let socket = match peer.ip() {
            IpAddr::V4(_) => TcpSocket::new_v4()?,
            IpAddr::V6(_) => TcpSocket::new_v6()?,
        };

        if let Some(pw) = password {
            #[cfg(target_os = "linux")]
            set_tcp_md5sig(&socket, peer.ip(), pw)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = pw;
                tracing::warn!("TCP_MD5SIG only supported on Linux; ignoring password");
            }
        }

        if let Some(src) = source {
            socket.bind(src)?;
        }

        let stream = tokio::time::timeout(connect_timeout, socket.connect(peer))
            .await
            .map_err(|_| {
                TransportError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("BGP connect to {} timed out", peer),
                ))
            })??;
        // Disable Nagle so KEEPALIVEs aren't delayed by 200ms.
        stream.set_nodelay(true)?;
        Ok(TokioTcpTransport {
            stream: Some(stream),
        })
    }

    /// Wrap an existing `TcpStream`. Used by the listener path
    /// when we accept inbound BGP connections (passive mode).
    pub fn from_accepted(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        TokioTcpTransport {
            stream: Some(stream),
        }
    }
}

#[async_trait]
impl BgpTransport for TokioTcpTransport {
    async fn send_message(&mut self, msg: &[u8]) -> Result<(), TransportError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            TransportError::Io(io::Error::new(io::ErrorKind::NotConnected, "closed"))
        })?;
        stream.write_all(msg).await?;
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Vec<u8>, TransportError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            TransportError::Io(io::Error::new(io::ErrorKind::NotConnected, "closed"))
        })?;
        // Read the 19-byte header first so we know the total length.
        let mut header = [0u8; HEADER_LEN];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(TransportError::Closed)
            }
            Err(e) => return Err(TransportError::Io(e)),
        }
        let parsed = Header::parse(&header).map_err(|e| TransportError::Header(e.to_string()))?;
        let total_len = parsed.length as usize;
        if total_len < HEADER_LEN || total_len > MAX_MESSAGE_LEN {
            return Err(TransportError::BadLength(total_len));
        }
        let mut buf = vec![0u8; total_len];
        buf[..HEADER_LEN].copy_from_slice(&header);
        if total_len > HEADER_LEN {
            stream.read_exact(&mut buf[HEADER_LEN..]).await?;
        }
        Ok(buf)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.stream.as_ref().and_then(|s| s.local_addr().ok())
    }
}

#[cfg(target_os = "linux")]
fn set_tcp_md5sig(socket: &TcpSocket, peer: IpAddr, password: &str) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // Linux UAPI: struct tcp_md5sig in <linux/tcp.h>.
    //   struct tcp_md5sig {
    //       struct __kernel_sockaddr_storage tcpm_addr;
    //       __u8   tcpm_flags;
    //       __u8   tcpm_prefixlen;
    //       __u16  tcpm_keylen;
    //       __u32  __tcpm_pad;
    //       __u8   tcpm_key[TCP_MD5SIG_MAXKEYLEN];  // 80
    //   };
    // Total size: 128 + 1 + 1 + 2 + 4 + 80 = 216 bytes.
    const TCP_MD5SIG: libc::c_int = 14;
    const TCP_MD5SIG_MAXKEYLEN: usize = 80;
    const SOCKADDR_STORAGE_SIZE: usize = 128;

    if password.len() > TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "TCP_MD5SIG key {} bytes exceeds max {}",
                password.len(),
                TCP_MD5SIG_MAXKEYLEN
            ),
        ));
    }

    let mut md5sig = [0u8; SOCKADDR_STORAGE_SIZE + 1 + 1 + 2 + 4 + TCP_MD5SIG_MAXKEYLEN];

    match peer {
        IpAddr::V4(v4) => {
            // sockaddr_in: family (2) + port (2) + addr (4) + 8 zero bytes.
            let family = libc::AF_INET as u16;
            md5sig[0..2].copy_from_slice(&family.to_ne_bytes());
            // port left as zero — TCP_MD5SIG ignores it.
            md5sig[4..8].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            let family = libc::AF_INET6 as u16;
            md5sig[0..2].copy_from_slice(&family.to_ne_bytes());
            // port + flowinfo left as zero.
            md5sig[8..24].copy_from_slice(&v6.octets());
        }
    }

    let keylen_off = SOCKADDR_STORAGE_SIZE + 1 + 1;
    let keylen = password.len() as u16;
    md5sig[keylen_off..keylen_off + 2].copy_from_slice(&keylen.to_ne_bytes());

    let key_off = SOCKADDR_STORAGE_SIZE + 1 + 1 + 2 + 4;
    md5sig[key_off..key_off + password.len()].copy_from_slice(password.as_bytes());

    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_MD5SIG,
            md5sig.as_ptr() as *const libc::c_void,
            md5sig.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---- VCL transport (feature-gated) ----

#[cfg(feature = "vcl")]
pub mod vcl_transport {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv6Addr};
    use tokio::sync::{mpsc, oneshot};

    use crate::adj_rib::PeerId;
    use crate::peer::PeerControl;

    /// Serialize the ENTIRE VCL session setup (worker registration +
    /// session create / bind / connect / listen / attr) across every
    /// VCL thread in the process — the per-peer active I/O threads AND
    /// the single passive-listener thread.
    ///
    /// libvppcom 25.10's worker-pool growth is not thread-safe:
    /// registering a worker reallocs `vcm->workers` and frees the old
    /// buffer, while concurrent threads inside `vppcom_session_create`
    /// (and the other session-setup calls) load `vcm->workers` and
    /// dereference it — racing the realloc faults on a freed pointer.
    /// `register_worker_thread`'s own lock only serializes
    /// register-vs-register; holding THIS lock across the whole setup
    /// makes registration and session creation strictly sequential
    /// across all VCL threads. It's dropped before any steady-state I/O
    /// loop, so live traffic isn't serialized.
    static VCL_SETUP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    enum IoCmd {
        Send(Vec<u8>, oneshot::Sender<Result<(), String>>),
        Close,
    }

    /// BGP transport backed by VPP's VCL TCP stack. All VCL I/O
    /// runs on a dedicated OS thread (VCL sessions are
    /// thread-local); the Tokio side communicates via channels.
    pub struct VclTransport {
        cmd_tx: Option<mpsc::Sender<IoCmd>>,
        /// Received messages pushed by the reader thread.
        msg_rx: mpsc::Receiver<Result<Vec<u8>, String>>,
        cached_local_addr: Option<SocketAddr>,
    }

    impl VclTransport {
        pub async fn connect(
            peer: SocketAddr,
            source: Option<SocketAddr>,
            _password: Option<&str>,
            _connect_timeout: Duration,
        ) -> Result<Self, TransportError> {
            if _password.is_some() {
                tracing::warn!(
                    "TCP_MD5SIG not supported via VCL; ignoring password for {}",
                    peer
                );
            }

            let (cmd_tx, cmd_rx) = mpsc::channel::<IoCmd>(64);
            let (msg_tx, msg_rx) = mpsc::channel::<Result<Vec<u8>, String>>(64);
            let (ready_tx, ready_rx) = oneshot::channel::<Result<Option<SocketAddr>, String>>();

            // Spawn a dedicated OS thread that owns the VCL
            // session for its entire lifetime.
            std::thread::Builder::new()
                .name(format!("vcl-{}", peer))
                .spawn(move || {
                    vcl_io_thread(peer, source, cmd_rx, msg_tx, ready_tx);
                })
                .map_err(|e| TransportError::Io(io::Error::new(io::ErrorKind::Other, e)))?;

            // Wait for the I/O thread to finish connecting.
            let result = ready_rx.await.map_err(|_| {
                TransportError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "VCL I/O thread died during connect",
                ))
            })?;
            let cached_local_addr = match result {
                Ok(addr) => addr,
                Err(e) => {
                    return Err(TransportError::Io(io::Error::new(io::ErrorKind::Other, e)));
                }
            };

            Ok(VclTransport {
                cmd_tx: Some(cmd_tx),
                msg_rx,
                cached_local_addr,
            })
        }

        /// Build a transport from channels wired to an externally-owned
        /// VCL session — used by the passive listener, which accepts a
        /// session on its own worker thread and services it there (VCL
        /// sessions are thread-local; an accepted session can't be moved
        /// to a per-peer thread). The listener feeds inbound messages
        /// into `msg_rx` and drains writes from the matching `cmd_tx`,
        /// so the peer FSM driver sees the same `BgpTransport` surface
        /// as the active path.
        fn from_channels(
            cmd_tx: mpsc::Sender<IoCmd>,
            msg_rx: mpsc::Receiver<Result<Vec<u8>, String>>,
            local_addr: Option<SocketAddr>,
        ) -> Self {
            VclTransport {
                cmd_tx: Some(cmd_tx),
                msg_rx,
                cached_local_addr: local_addr,
            }
        }
    }

    /// The I/O thread: registers as a VCL worker, creates and
    /// connects the session, then loops dispatching commands from
    /// the Tokio side.
    fn vcl_io_thread(
        peer: SocketAddr,
        source: Option<SocketAddr>,
        mut cmd_rx: mpsc::Receiver<IoCmd>,
        msg_tx: mpsc::Sender<Result<Vec<u8>, String>>,
        ready_tx: oneshot::Sender<Result<Option<SocketAddr>, String>>,
    ) {
        // Serialize the ENTIRE VCL session setup (worker registration +
        // session create / bind / connect / attr) across all VCL threads —
        // see `VCL_SETUP_LOCK` for the libvppcom 25.10 worker-pool-realloc
        // race this guards against. Dropped before the steady-state I/O loop
        // so live traffic isn't serialized.
        let setup_guard = VCL_SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Register this dedicated per-peer I/O thread as a VCL worker via
        // vcl-rs's serialized wrapper, NOT the raw FFI.
        vcl_rs::register_worker_thread();

        // Create a BLOCKING session for simplicity — reads block
        // on the thread, which is fine since it's dedicated.
        let sh = unsafe { vcl_rs::ffi::vppcom_session_create(vcl_rs::ffi::VPPCOM_PROTO_TCP, 0) };
        if sh < 0 {
            let _ = ready_tx.send(Err(format!("session_create failed: {}", sh)));
            return;
        }
        let sh = sh as u32;

        // Bind source if configured.
        if let Some(src) = source {
            let mut src_ip_buf = [0u8; 16];
            let mut ep = vcl_rs::session::endpoint_into_buf(src, &mut src_ip_buf);
            let rc = unsafe { vcl_rs::ffi::vppcom_session_bind(sh, &mut ep) };
            if rc < 0 {
                let _ = ready_tx.send(Err(format!("bind failed: {}", rc)));
                unsafe { vcl_rs::ffi::vppcom_session_close(sh); }
                return;
            }
        }

        // Connect (blocking).
        let mut peer_ip_buf = [0u8; 16];
        let mut ep = vcl_rs::session::endpoint_into_buf(peer, &mut peer_ip_buf);
        let rc = unsafe { vcl_rs::ffi::vppcom_session_connect(sh, &mut ep) };
        if rc < 0 {
            let _ = ready_tx.send(Err(format!("connect to {} failed: {}", peer, rc)));
            unsafe { vcl_rs::ffi::vppcom_session_close(sh); }
            return;
        }

        // Set TCP_NODELAY.
        let val: u32 = 1;
        let mut len = 4u32;
        unsafe {
            vcl_rs::ffi::vppcom_session_attr(
                sh,
                vcl_rs::ffi::VPPCOM_ATTR_SET_TCP_NODELAY,
                &val as *const _ as *mut _,
                &mut len,
            );
        }

        // Query the local address before signalling ready — this
        // avoids the cross-thread timing issue with local_addr().
        let local_addr = {
            let mut ip_buf = [0u8; 16];
            let mut ep = vcl_rs::ffi::vppcom_endpt_t {
                ip: ip_buf.as_mut_ptr(),
                ..Default::default()
            };
            let mut len = std::mem::size_of::<vcl_rs::ffi::vppcom_endpt_t>() as u32;
            let rc = unsafe {
                vcl_rs::ffi::vppcom_session_attr(
                    sh,
                    vcl_rs::ffi::VPPCOM_ATTR_GET_LCL_ADDR,
                    &mut ep as *mut _ as *mut _,
                    &mut len,
                )
            };
            if rc >= 0 {
                let port = u16::from_be(ep.port);
                if ep.is_ip4 != 0 {
                    let mut o = [0u8; 4];
                    o.copy_from_slice(&ip_buf[..4]);
                    Some(SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(o)),
                        port,
                    ))
                } else {
                    Some(SocketAddr::new(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_buf)),
                        port,
                    ))
                }
            } else {
                None
            }
        };
        // Split into a reader thread (continuously reads BGP
        // messages and pushes to msg_tx) and a writer loop (this
        // thread handles Send/Close commands). VCL sessions are
        // thread-local, but read and write on the same session
        // from the same thread is safe. We use the SAME thread
        // for both by making reads non-blocking and polling.
        //
        // Simpler approach: since VCL sessions can't be shared
        // across threads, we switch the session to non-blocking
        // and alternate between reading and checking commands.
        let flags: u32 = libc::O_NONBLOCK as u32;
        let mut flen = std::mem::size_of::<u32>() as u32;
        unsafe {
            vcl_rs::ffi::vppcom_session_attr(
                sh,
                vcl_rs::ffi::VPPCOM_ATTR_SET_FLAGS,
                &flags as *const _ as *mut _,
                &mut flen,
            );
        }

        // VCL setup complete — release the setup lock before the I/O loop so
        // steady-state reads/writes across peers are not serialized.
        drop(setup_guard);

        let _ = ready_tx.send(Ok(local_addr));

        // Main I/O loop: poll for reads and check for write
        // commands, all on this single thread.
        loop {
            // Try to read a BGP message (non-blocking).
            let mut header = [0u8; HEADER_LEN];
            match read_exact_vcl_nb(sh, &mut header) {
                Ok(true) => {
                    // Got a full header.
                    let total_len =
                        u16::from_be_bytes([header[16], header[17]]) as usize;
                    if total_len < HEADER_LEN || total_len > MAX_MESSAGE_LEN {
                        let _ = msg_tx.blocking_send(Err(format!(
                            "bad length {}",
                            total_len
                        )));
                        break;
                    }
                    let mut buf = vec![0u8; total_len];
                    buf[..HEADER_LEN].copy_from_slice(&header);
                    if total_len > HEADER_LEN {
                        // Body read: block until complete (we have
                        // the header, the body must follow).
                        match read_exact_vcl(sh, &mut buf[HEADER_LEN..]) {
                            Ok(()) => {}
                            Err(e) => {
                                let _ = msg_tx.blocking_send(Err(e));
                                break;
                            }
                        }
                    }
                    if msg_tx.blocking_send(Ok(buf)).is_err() {
                        break;
                    }
                }
                Ok(false) => {
                    // No data available — check for write commands.
                }
                Err(e) => {
                    let _ = msg_tx.blocking_send(Err(e));
                    break;
                }
            }

            // Process pending write commands (non-blocking).
            match cmd_rx.try_recv() {
                Ok(IoCmd::Send(data, reply)) => {
                    let mut pos = 0;
                    let mut err = None;
                    while pos < data.len() {
                        let rc = unsafe {
                            vcl_rs::ffi::vppcom_session_write(
                                sh,
                                data[pos..].as_ptr() as *mut _,
                                data.len() - pos,
                            )
                        };
                        if rc < 0 && rc != -libc::EAGAIN {
                            err = Some(format!("write failed: {}", rc));
                            break;
                        }
                        if rc > 0 {
                            pos += rc as usize;
                        }
                        if rc == -libc::EAGAIN || rc == 0 {
                            std::thread::sleep(Duration::from_micros(100));
                        }
                    }
                    let _ = reply.send(match err {
                        None => Ok(()),
                        Some(e) => Err(e),
                    });
                }
                Ok(IoCmd::Close) => break,
                Err(mpsc::error::TryRecvError::Empty) => {
                    // No commands — sleep briefly to avoid busy-loop.
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        unsafe {
            vcl_rs::ffi::vppcom_session_close(sh);
        }
    }

    /// Non-blocking read attempt. Returns Ok(true) if `buf` was
    /// fully filled, Ok(false) if no data is available yet, or
    /// Err on connection error.
    fn read_exact_vcl_nb(sh: u32, buf: &mut [u8]) -> Result<bool, String> {
        let mut pos = 0;
        while pos < buf.len() {
            let rc = unsafe {
                vcl_rs::ffi::vppcom_session_read(
                    sh,
                    buf[pos..].as_mut_ptr() as *mut _,
                    buf.len() - pos,
                )
            };
            if rc == -libc::EAGAIN || rc == -libc::EWOULDBLOCK {
                if pos == 0 {
                    return Ok(false);
                }
                // Partial read — keep trying (we have some bytes,
                // the rest must follow).
                std::thread::sleep(Duration::from_micros(100));
                continue;
            }
            if rc <= 0 {
                return Err(format!("read failed: {}", rc));
            }
            pos += rc as usize;
        }
        Ok(true)
    }

    fn read_exact_vcl(sh: u32, buf: &mut [u8]) -> Result<(), String> {
        let mut pos = 0;
        while pos < buf.len() {
            let rc = unsafe {
                vcl_rs::ffi::vppcom_session_read(
                    sh,
                    buf[pos..].as_mut_ptr() as *mut _,
                    buf.len() - pos,
                )
            };
            // A BGP body can span multiple TCP segments; on a
            // non-blocking session the next chunk may not be ready yet.
            // Spin (the header already committed us to reading the rest)
            // rather than mistaking EAGAIN for a closed connection.
            if rc == -libc::EAGAIN || rc == -libc::EWOULDBLOCK {
                std::thread::sleep(Duration::from_micros(100));
                continue;
            }
            if rc <= 0 {
                return Err(format!("read failed: {}", rc));
            }
            pos += rc as usize;
        }
        Ok(())
    }

    /// Try to read exactly one BGP message from a non-blocking VCL
    /// session. `Ok(None)` means no message is pending yet (EAGAIN with
    /// nothing buffered); `Ok(Some(bytes))` is a full message
    /// (header + body); `Err` is a real read/framing error. Used by the
    /// passive listener to multiplex many accepted sessions on one
    /// worker thread without blocking on any single idle peer.
    fn try_read_message_vcl(sh: u32) -> Result<Option<Vec<u8>>, String> {
        let mut header = [0u8; HEADER_LEN];
        match read_exact_vcl_nb(sh, &mut header)? {
            false => return Ok(None),
            true => {}
        }
        let total_len = u16::from_be_bytes([header[16], header[17]]) as usize;
        if total_len < HEADER_LEN || total_len > MAX_MESSAGE_LEN {
            return Err(format!("bad length {}", total_len));
        }
        let mut buf = vec![0u8; total_len];
        buf[..HEADER_LEN].copy_from_slice(&header);
        if total_len > HEADER_LEN {
            read_exact_vcl(sh, &mut buf[HEADER_LEN..])?;
        }
        Ok(Some(buf))
    }

    /// Write `data` in full to a VCL session, spinning over EAGAIN /
    /// short writes. Shared by the active I/O thread and the passive
    /// listener.
    fn write_all_vcl(sh: u32, data: &[u8]) -> Result<(), String> {
        let mut pos = 0;
        while pos < data.len() {
            let rc = unsafe {
                vcl_rs::ffi::vppcom_session_write(
                    sh,
                    data[pos..].as_ptr() as *mut _,
                    data.len() - pos,
                )
            };
            if rc < 0 && rc != -libc::EAGAIN {
                return Err(format!("write failed: {}", rc));
            }
            if rc > 0 {
                pos += rc as usize;
            }
            if rc == -libc::EAGAIN || rc == 0 {
                std::thread::sleep(Duration::from_micros(100));
            }
        }
        Ok(())
    }

    /// Set TCP_NODELAY on a VCL session (Nagle off so KEEPALIVEs aren't
    /// delayed).
    fn set_session_nodelay(sh: u32) {
        let val: u32 = 1;
        let mut len = 4u32;
        unsafe {
            vcl_rs::ffi::vppcom_session_attr(
                sh,
                vcl_rs::ffi::VPPCOM_ATTR_SET_TCP_NODELAY,
                &val as *const _ as *mut _,
                &mut len,
            );
        }
    }

    /// Switch a VCL session to non-blocking mode (so reads return
    /// EAGAIN instead of parking the worker thread).
    fn set_session_nonblocking(sh: u32) {
        let flags: u32 = libc::O_NONBLOCK as u32;
        let mut flen = std::mem::size_of::<u32>() as u32;
        unsafe {
            vcl_rs::ffi::vppcom_session_attr(
                sh,
                vcl_rs::ffi::VPPCOM_ATTR_SET_FLAGS,
                &flags as *const _ as *mut _,
                &mut flen,
            );
        }
    }

    /// Query the local 5-tuple address of a connected/accepted VCL
    /// session (used as the BGP next-hop for "next-hop self").
    fn query_local_addr_vcl(sh: u32) -> Option<SocketAddr> {
        let mut ip_buf = [0u8; 16];
        let mut ep = vcl_rs::ffi::vppcom_endpt_t {
            ip: ip_buf.as_mut_ptr(),
            ..Default::default()
        };
        let mut len = std::mem::size_of::<vcl_rs::ffi::vppcom_endpt_t>() as u32;
        let rc = unsafe {
            vcl_rs::ffi::vppcom_session_attr(
                sh,
                vcl_rs::ffi::VPPCOM_ATTR_GET_LCL_ADDR,
                &mut ep as *mut _ as *mut _,
                &mut len,
            )
        };
        if rc < 0 {
            return None;
        }
        Some(socketaddr_from_endpt(&ep, &ip_buf))
    }

    /// Reconstruct a `SocketAddr` from a VCL endpoint + its IP buffer.
    fn socketaddr_from_endpt(ep: &vcl_rs::ffi::vppcom_endpt_t, ip_buf: &[u8; 16]) -> SocketAddr {
        let port = u16::from_be(ep.port);
        if ep.is_ip4 != 0 {
            let mut o = [0u8; 4];
            o.copy_from_slice(&ip_buf[..4]);
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(o)), port)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip_buf)), port)
        }
    }

    /// One accepted, listener-owned VCL session and the channels that
    /// bridge it to the peer FSM driver's `VclTransport`.
    struct AcceptedSession {
        sh: u32,
        peer_id: PeerId,
        /// Writes from the peer driver to push onto the wire.
        cmd_rx: mpsc::Receiver<IoCmd>,
        /// Inbound messages read off the wire, delivered to the driver.
        msg_tx: mpsc::Sender<Result<Vec<u8>, String>>,
    }

    /// Spawn the passive BGP listener over VPP's VCL stack. A single
    /// dedicated worker thread binds/listens and ALSO services every
    /// accepted session — VCL sessions are thread-local (an accepted
    /// session lives in the accepting worker's pool and libvppcom
    /// exposes no session→worker migration), so the listen socket and
    /// its children must share one worker. Inbound connections from a
    /// known peer IP are wrapped in a channel-backed `VclTransport` and
    /// injected into that peer's FSM via `PeerControl::InjectTransport`;
    /// unknown sources are closed.
    pub fn spawn_vcl_listener(
        listen_addr: SocketAddr,
        peer_map: HashMap<IpAddr, (PeerId, mpsc::Sender<PeerControl>)>,
    ) -> io::Result<()> {
        std::thread::Builder::new()
            .name("vcl-bgp-listener".into())
            .spawn(move || vcl_listener_thread(listen_addr, peer_map))?;
        Ok(())
    }

    fn vcl_listener_thread(
        listen_addr: SocketAddr,
        peer_map: HashMap<IpAddr, (PeerId, mpsc::Sender<PeerControl>)>,
    ) {
        // Serialize listen-session setup against the active threads'
        // session setup — same libvppcom worker-pool-realloc race.
        let setup_guard = VCL_SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        vcl_rs::register_worker_thread();

        // Non-blocking listen session so accept() returns EAGAIN
        // instead of parking the worker (which also services accepted
        // sessions).
        let listen_sh =
            unsafe { vcl_rs::ffi::vppcom_session_create(vcl_rs::ffi::VPPCOM_PROTO_TCP, 1) };
        if listen_sh < 0 {
            tracing::error!("VCL listener session_create failed: {}", listen_sh);
            return;
        }
        let listen_sh = listen_sh as u32;

        let mut ip_buf = [0u8; 16];
        let mut ep = vcl_rs::session::endpoint_into_buf(listen_addr, &mut ip_buf);
        let rc = unsafe { vcl_rs::ffi::vppcom_session_bind(listen_sh, &mut ep) };
        if rc < 0 {
            tracing::error!(%listen_addr, "VCL listener bind failed: {}", rc);
            unsafe { vcl_rs::ffi::vppcom_session_close(listen_sh) };
            return;
        }
        let rc = unsafe { vcl_rs::ffi::vppcom_session_listen(listen_sh, 16) };
        if rc < 0 {
            tracing::error!(%listen_addr, "VCL listener listen failed: {}", rc);
            unsafe { vcl_rs::ffi::vppcom_session_close(listen_sh) };
            return;
        }
        drop(setup_guard);
        tracing::info!(%listen_addr, "VCL BGP listener bound (passive open)");

        let mut sessions: Vec<AcceptedSession> = Vec::new();

        loop {
            // 1. Drain any pending inbound connections (non-blocking).
            loop {
                let mut aip = [0u8; 16];
                let mut aep = vcl_rs::ffi::vppcom_endpt_t {
                    ip: aip.as_mut_ptr(),
                    ..Default::default()
                };
                let rc = unsafe { vcl_rs::ffi::vppcom_session_accept(listen_sh, &mut aep, 0) };
                if rc == -libc::EAGAIN || rc == -libc::EWOULDBLOCK {
                    break;
                }
                if rc < 0 {
                    tracing::warn!("VCL listener accept error: {}", rc);
                    break;
                }
                let new_sh = rc as u32;
                let peer_ip = if aep.is_ip4 != 0 {
                    let mut o = [0u8; 4];
                    o.copy_from_slice(&aip[..4]);
                    IpAddr::V4(std::net::Ipv4Addr::from(o))
                } else {
                    IpAddr::V6(Ipv6Addr::from(aip))
                };

                set_session_nonblocking(new_sh);
                set_session_nodelay(new_sh);

                match peer_map.get(&peer_ip) {
                    Some((peer_id, control_tx)) => {
                        let local_addr = query_local_addr_vcl(new_sh);
                        let (cmd_tx, cmd_rx) = mpsc::channel::<IoCmd>(64);
                        let (msg_tx, msg_rx) =
                            mpsc::channel::<Result<Vec<u8>, String>>(64);
                        let transport =
                            VclTransport::from_channels(cmd_tx, msg_rx, local_addr);
                        if control_tx
                            .blocking_send(PeerControl::InjectTransport(Box::new(transport)))
                            .is_ok()
                        {
                            tracing::info!(
                                %peer_ip,
                                peer_id,
                                "accepted inbound BGP connection (VCL)"
                            );
                            sessions.push(AcceptedSession {
                                sh: new_sh,
                                peer_id: *peer_id,
                                cmd_rx,
                                msg_tx,
                            });
                        } else {
                            // Peer task gone — drop the session.
                            unsafe { vcl_rs::ffi::vppcom_session_close(new_sh) };
                        }
                    }
                    None => {
                        tracing::warn!(
                            %peer_ip,
                            "rejected inbound VCL BGP connection from unknown peer"
                        );
                        unsafe { vcl_rs::ffi::vppcom_session_close(new_sh) };
                    }
                }
            }

            // 2. Service every accepted session: deliver inbound
            //    messages and drain outbound writes, all non-blocking.
            let mut i = 0;
            while i < sessions.len() {
                let mut drop_session = false;

                match try_read_message_vcl(sessions[i].sh) {
                    Ok(Some(buf)) => {
                        if sessions[i].msg_tx.blocking_send(Ok(buf)).is_err() {
                            // Driver dropped its receiver — session done.
                            drop_session = true;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        let _ = sessions[i].msg_tx.blocking_send(Err(e));
                        drop_session = true;
                    }
                }

                if !drop_session {
                    loop {
                        match sessions[i].cmd_rx.try_recv() {
                            Ok(IoCmd::Send(data, reply)) => {
                                let r = write_all_vcl(sessions[i].sh, &data);
                                let failed = r.is_err();
                                let _ = reply.send(r);
                                if failed {
                                    drop_session = true;
                                    break;
                                }
                            }
                            Ok(IoCmd::Close) => {
                                drop_session = true;
                                break;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                drop_session = true;
                                break;
                            }
                        }
                    }
                }

                if drop_session {
                    tracing::debug!(
                        peer_id = sessions[i].peer_id,
                        "closing accepted VCL BGP session"
                    );
                    unsafe { vcl_rs::ffi::vppcom_session_close(sessions[i].sh) };
                    sessions.swap_remove(i);
                } else {
                    i += 1;
                }
            }

            // Avoid a busy spin when idle.
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn map_io_err(e: String) -> TransportError {
        if e.contains("failed: 0") || e.contains("failed: -104") || e.contains("failed: -32") {
            TransportError::Closed
        } else {
            TransportError::Io(io::Error::new(io::ErrorKind::Other, e))
        }
    }

    #[async_trait]
    impl BgpTransport for VclTransport {
        async fn send_message(&mut self, msg: &[u8]) -> Result<(), TransportError> {
            let tx = self.cmd_tx.as_ref().ok_or(TransportError::Closed)?;
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(IoCmd::Send(msg.to_vec(), reply_tx))
                .await
                .map_err(|_| TransportError::Closed)?;
            reply_rx
                .await
                .map_err(|_| TransportError::Closed)?
                .map_err(map_io_err)
        }

        async fn recv_message(&mut self) -> Result<Vec<u8>, TransportError> {
            self.msg_rx
                .recv()
                .await
                .ok_or(TransportError::Closed)?
                .map_err(map_io_err)
        }

        async fn close(&mut self) -> Result<(), TransportError> {
            if let Some(tx) = self.cmd_tx.take() {
                let _ = tx.send(IoCmd::Close).await;
            }
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            self.cached_local_addr
        }
    }
}

#[cfg(feature = "vcl")]
pub use vcl_transport::VclTransport;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{header::MessageType, keepalive};
    use tokio::net::TcpListener;

    /// End-to-end smoke test: open a localhost TCP listener,
    /// connect from `TokioTcpTransport`, send a KEEPALIVE one way
    /// and verify the receiver decodes a valid header. No
    /// TCP_MD5SIG (would need root + matching key on both sides).
    #[tokio::test]
    async fn keepalive_roundtrip_localhost() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut t = TokioTcpTransport::from_accepted(sock);
            let msg = t.recv_message().await.unwrap();
            // First (and only) message should parse as a KEEPALIVE.
            let h = Header::parse(&msg).unwrap();
            assert_eq!(h.msg_type, MessageType::Keepalive);
            assert_eq!(h.length as usize, msg.len());
        });

        let mut client = TokioTcpTransport::connect(
            addr,
            None,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        client.send_message(&keepalive::encode()).await.unwrap();
        client.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn recv_returns_closed_on_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Server accepts and immediately closes.
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            drop(sock);
        });
        let mut client = TokioTcpTransport::connect(
            addr,
            None,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let err = client.recv_message().await.unwrap_err();
        assert!(matches!(err, TransportError::Closed));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_timeout_fires() {
        // 192.0.2.0/24 is TEST-NET-1; nothing should answer.
        let dest = "192.0.2.1:179".parse().unwrap();
        let err = TokioTcpTransport::connect(
            dest,
            None,
            None,
            Duration::from_millis(150),
        )
        .await
        .unwrap_err();
        match err {
            TransportError::Io(e) => {
                // Either TimedOut from our wrapper, or a quick
                // network-unreachable from the kernel; both are
                // acceptable failure modes for this test.
                assert!(matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::HostUnreachable
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::ConnectionRefused
                ));
            }
            other => panic!("expected I/O error, got {:?}", other),
        }
    }
}
