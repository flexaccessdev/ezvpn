//! End-to-end check of the data-stream framing over a real iroh QUIC
//! connection (loopback only: relays and discovery disabled).
//!
//! The unit tests in `tunnel::stream` cover encode/decode in memory; this
//! exercises the actual stream I/O — `read_frame`'s length-prefix reads and
//! clean end-of-stream detection, and `write_frames`' vectored chunk writes —
//! against the same iroh QUIC stack the tunnel runs on, including a frame
//! larger than any single QUIC packet.

use bytes::BytesMut;
use ezvpn::transport::build_quic_transport_config;
use ezvpn::tunnel::signaling::{ServerAddrsMsg, parse_ip_packet_v2};
use ezvpn::tunnel::stream::{
    Frame, MAX_FRAME_BODY, classify, encode_ip_frame, encode_server_addrs_frame, read_frame,
    write_frames,
};
use iroh::{Endpoint, RelayMode, endpoint::presets};
use std::sync::Arc;

const TEST_ALPN: &[u8] = b"ezvpn-stream-test/0";

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

#[tokio::test]
async fn frames_roundtrip_over_quic_stream() {
    let server = bind_endpoint().await;
    let client = bind_endpoint().await;
    let server_addr = server.addr();

    // Echo server: accept one connection + bi-stream, echo every frame back
    // verbatim, finish cleanly when the client finishes its send half.
    let accept_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming connection");
        let conn = incoming.await.expect("accept connection");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let mut buf = vec![0u8; MAX_FRAME_BODY];
        let mut echo = BytesMut::new();
        while let Some(len) = read_frame(&mut recv, &mut buf).await.expect("server read") {
            echo.extend_from_slice(&(len as u32).to_be_bytes());
            echo.extend_from_slice(&buf[..len]);
            let mut pending = vec![echo.split().freeze()];
            write_frames(&mut send, &mut pending).await.expect("echo frame");
        }
        send.finish().expect("finish echo stream");
        // Keep the connection alive until the client closes it.
        conn.closed().await;
    });

    let conn = client
        .connect(server_addr, TEST_ALPN)
        .await
        .expect("connect to server");
    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");

    // Three frames in one vectored write: a minimal IP packet, a 9000-byte
    // packet (crosses many QUIC packets — impossible under the old datagram
    // mapping without resegmentation), and a server-addrs message.
    let small = {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p
    };
    let big = {
        let mut p = vec![0xA5u8; 9000];
        p[0] = 0x45;
        p
    };
    let addrs_msg = ServerAddrsMsg::new(vec!["203.0.113.9".parse().expect("addr")]);
    let mut arena = BytesMut::new();
    encode_ip_frame(&mut arena, None, &small).expect("encode small");
    encode_ip_frame(&mut arena, None, &big).expect("encode big");
    encode_server_addrs_frame(&mut arena, &addrs_msg).expect("encode addrs");
    let mut pending = vec![arena.freeze()];
    write_frames(&mut send, &mut pending).await.expect("write frames");
    assert!(pending.is_empty(), "write_frames drains the batch");
    send.finish().expect("finish send half");

    let mut buf = vec![0u8; MAX_FRAME_BODY];

    let len = read_frame(&mut recv, &mut buf)
        .await
        .expect("read frame 1")
        .expect("frame 1 present");
    match classify(&buf[..len]).expect("classify frame 1") {
        Frame::Ip(body) => {
            let (offload, ip) = parse_ip_packet_v2(body).expect("parse frame 1");
            assert!(offload.is_none());
            assert_eq!(ip, &small[..]);
        }
        other => panic!("expected Ip, got {other:?}"),
    }

    let len = read_frame(&mut recv, &mut buf)
        .await
        .expect("read frame 2")
        .expect("frame 2 present");
    match classify(&buf[..len]).expect("classify frame 2") {
        Frame::Ip(body) => {
            let (offload, ip) = parse_ip_packet_v2(body).expect("parse frame 2");
            assert!(offload.is_none());
            assert_eq!(ip, &big[..], "9000-byte frame must survive intact");
        }
        other => panic!("expected Ip, got {other:?}"),
    }

    let len = read_frame(&mut recv, &mut buf)
        .await
        .expect("read frame 3")
        .expect("frame 3 present");
    match classify(&buf[..len]).expect("classify frame 3") {
        Frame::ServerAddrs(body) => {
            assert_eq!(ServerAddrsMsg::decode(body).expect("decode addrs"), addrs_msg);
        }
        other => panic!("expected ServerAddrs, got {other:?}"),
    }

    // The echo side finished after our finish: clean end-of-stream, not error.
    assert!(
        read_frame(&mut recv, &mut buf)
            .await
            .expect("read eof")
            .is_none(),
        "peer finish must surface as a clean end-of-stream"
    );

    conn.close(0u32.into(), b"done");
    accept_task.await.expect("server task");
    client.close().await;
}
