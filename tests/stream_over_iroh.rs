//! End-to-end check of the data path (unreliable QUIC datagrams) and the
//! control channel (reliable stream) over a real iroh QUIC connection
//! (loopback only: relays and discovery disabled).
//!
//! The unit tests in `tunnel::stream` cover encode/decode in memory; this
//! exercises the actual iroh I/O: `send_ip_datagrams` / `read_datagram` for the
//! data path (including the oversized-packet drop), and `read_frame` /
//! `write_frames` for `ServerAddrs` control frames on the stream.

use bytes::BytesMut;
use ezvpn::transport::build_quic_transport_config;
use ezvpn::tunnel::signaling::ServerAddrsMsg;
use ezvpn::tunnel::stream::{
    Frame, MAX_FRAME_BODY, classify, encode_server_addrs_frame, read_frame, send_ip_datagrams,
    write_frames,
};
use iroh::{Endpoint, RelayMode, endpoint::presets};
use std::sync::Arc;

const TEST_ALPN: &[u8] = b"ezvpn-datagram-test/0";

async fn bind_endpoint() -> Endpoint {
    Endpoint::builder(presets::Empty)
        .relay_mode(RelayMode::Disabled)
        .transport_config(build_quic_transport_config().expect("transport config"))
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .expect("bind endpoint")
}

/// An IP packet maps directly to one unreliable datagram and round-trips
/// intact; a packet larger than the live datagram size is dropped, not sent.
#[tokio::test]
async fn ip_packets_roundtrip_as_datagrams() {
    let server = bind_endpoint().await;
    let client = bind_endpoint().await;
    let server_addr = server.addr();

    // Echo server: accept one connection, echo every datagram back verbatim
    // until the connection closes.
    let accept_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming connection");
        let conn = incoming.await.expect("accept connection");
        while let Ok(datagram) = conn.read_datagram().await {
            if conn.send_datagram(datagram).is_err() {
                break;
            }
        }
    });

    let conn = client
        .connect(server_addr, TEST_ALPN)
        .await
        .expect("connect to server");

    let mut arena = BytesMut::new();
    let mut seg_scratch: Vec<u8> = Vec::new();

    // A minimal IP packet fits in one datagram and round-trips intact.
    let small = {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p
    };
    let outcome = send_ip_datagrams(&conn, &mut arena, &mut seg_scratch, None, &small);
    assert_eq!(outcome.sent, 1, "small packet is sent as one datagram");
    assert_eq!(outcome.dropped_too_large, 0);

    let echoed = conn.read_datagram().await.expect("read echoed datagram");
    assert_eq!(&echoed[..], &small[..], "datagram round-trips intact");

    // A 9000-byte packet exceeds any datagram size and is dropped, not sent.
    let big = {
        let mut p = vec![0xA5u8; 9000];
        p[0] = 0x45;
        p
    };
    let outcome = send_ip_datagrams(&conn, &mut arena, &mut seg_scratch, None, &big);
    assert_eq!(outcome.sent, 0, "oversized packet is never sent");
    assert_eq!(
        outcome.dropped_too_large, 1,
        "oversized packet is dropped, not fragmented"
    );

    conn.close(0u32.into(), b"done");
    let _ = accept_task.await;
    client.close().await;
}

/// A `ServerAddrs` control frame round-trips over the reliable stream.
#[tokio::test]
async fn server_addrs_frame_roundtrips_over_stream() {
    let server = bind_endpoint().await;
    let client = bind_endpoint().await;
    let server_addr = server.addr();

    let addrs_msg = ServerAddrsMsg::new(vec!["203.0.113.9".parse().expect("addr")]);

    // Echo server: reads one control frame off the accepted bi-stream and
    // writes it straight back, then stays up until the client closes.
    let accept_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming connection");
        let conn = incoming.await.expect("accept connection");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let mut buf = vec![0u8; MAX_FRAME_BODY];
        let len = read_frame(&mut recv, &mut buf)
            .await
            .expect("read frame")
            .expect("frame present");
        // Re-prefix with the length so the echo is a well-formed frame.
        let mut framed = BytesMut::new();
        framed.extend_from_slice(&(len as u32).to_be_bytes());
        framed.extend_from_slice(&buf[..len]);
        let mut echo = vec![framed.freeze()];
        write_frames(&mut send, &mut echo).await.expect("echo frame");
        send.finish().expect("finish echo stream");
        conn.closed().await;
    });

    let conn = client
        .connect(server_addr, TEST_ALPN)
        .await
        .expect("connect to server");
    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");

    let mut arena = BytesMut::new();
    encode_server_addrs_frame(&mut arena, &addrs_msg).expect("encode addrs");
    let mut pending = vec![arena.freeze()];
    write_frames(&mut send, &mut pending).await.expect("write frame");
    send.finish().expect("finish send half");

    // Read the echoed frame back — confirms the server received and framed it.
    let mut buf = vec![0u8; MAX_FRAME_BODY];
    let len = read_frame(&mut recv, &mut buf)
        .await
        .expect("read echo")
        .expect("echo present");
    match classify(&buf[..len]).expect("classify") {
        Frame::ServerAddrs(body) => {
            assert_eq!(ServerAddrsMsg::decode(body).expect("decode addrs"), addrs_msg);
        }
    }

    conn.close(0u32.into(), b"done");
    accept_task.await.expect("server task");
    client.close().await;
}
