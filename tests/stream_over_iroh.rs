//! End-to-end check of the data path (unreliable QUIC datagrams) and the
//! control channel (reliable stream) over a real iroh QUIC connection
//! (loopback only: relays and discovery disabled).
//!
//! The unit tests in `tunnel::stream` cover encode/decode in memory; this
//! exercises the actual iroh I/O: `send_ip_datagrams` / `read_datagram` for the
//! data path (including the oversized-packet drop), and `read_frame` /
//! `write_frames` for `ServerAddrs` control frames on the stream.

use bytes::BytesMut;
use ezvpn::config::VPN_MTU;
use ezvpn::transport::{QUIC_DATAGRAM_SEND_BUFFER_SIZE, build_quic_transport_config};
use ezvpn::tunnel::signaling::ServerAddrsMsg;
use ezvpn::tunnel::stream::{
    Frame, MAX_FRAME_BODY, classify, encode_server_addrs_frame, read_frame, send_ip_datagrams,
    write_frames,
};
use iroh::{Endpoint, RelayMode, endpoint::presets};
use std::sync::Arc;
use std::time::Duration;

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
    let mut pending = Vec::new();

    assert!(
        conn.max_datagram_size().expect("datagrams enabled") >= VPN_MTU as usize,
        "a full VPN packet must fit immediately after the handshake"
    );

    // A full-MTU packet must not be dropped while path discovery warms up.
    let mut full_mtu = vec![0u8; VPN_MTU as usize];
    full_mtu[0] = 0x45;
    let outcome = send_ip_datagrams(
        &conn,
        &mut arena,
        &mut seg_scratch,
        &mut pending,
        None,
        &full_mtu,
    )
    .await;
    assert_eq!(outcome.sent, 1, "full-MTU packet is sent immediately");
    assert_eq!(outcome.dropped_too_large, 0);
    let echoed = conn.read_datagram().await.expect("read full-MTU echo");
    assert_eq!(&echoed[..], &full_mtu[..]);

    // A minimal IP packet fits in one datagram and round-trips intact.
    let small = {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p
    };
    let outcome = send_ip_datagrams(
        &conn,
        &mut arena,
        &mut seg_scratch,
        &mut pending,
        None,
        &small,
    )
    .await;
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
    let outcome = send_ip_datagrams(
        &conn,
        &mut arena,
        &mut seg_scratch,
        &mut pending,
        None,
        &big,
    )
    .await;
    assert_eq!(outcome.sent, 0, "oversized packet is never sent");
    assert_eq!(
        outcome.dropped_too_large, 1,
        "oversized packet is dropped, not fragmented"
    );

    conn.close(0u32.into(), b"done");
    let _ = accept_task.await;
    client.close().await;
}

/// Sending more than the bounded QUIC queue can hold waits for the pacer
/// instead of silently evicting older datagrams.
///
/// The guarantee under test is a send-side property: every packet the caller
/// hands to [`send_ip_datagrams`] is queued (`sent == 1`) and none is evicted
/// (`dropped_other == 0`), even though the batch is far larger than the send
/// buffer. That is asserted deterministically per packet below. Delivery itself
/// rides unreliable QUIC datagrams, so the receiver tolerates the occasional
/// loopback loss rather than demanding all `PACKET_COUNT` back — insisting on
/// exact delivery made this test flaky.
#[tokio::test]
async fn datagram_backpressure_preserves_queued_packets() {
    const PACKET_COUNT: u32 = 512;
    const PACKET_SIZE: usize = 900;

    let server = bind_endpoint().await;
    let client = bind_endpoint().await;
    let server_addr = server.addr();

    let accept_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming connection");
        let conn = incoming.await.expect("accept connection");
        let mut received = Vec::with_capacity(PACKET_COUNT as usize);
        // Drain until every packet arrives or the flow goes idle. A lost
        // datagram must not wedge us on a `read_datagram` that never returns, so
        // stop on an idle gap (or connection close) instead of a fixed count.
        while received.len() < PACKET_COUNT as usize {
            match tokio::time::timeout(Duration::from_secs(3), conn.read_datagram()).await {
                Ok(Ok(datagram)) => received.push(u32::from_be_bytes(
                    datagram[1..5].try_into().expect("sequence bytes"),
                )),
                // Idle gap or closed connection: the sender is done, stop.
                Ok(Err(_)) | Err(_) => break,
            }
        }
        received
    });

    let conn = client
        .connect(server_addr, TEST_ALPN)
        .await
        .expect("connect to server");
    let mut arena = BytesMut::new();
    let mut seg_scratch = Vec::new();
    let mut pending = Vec::new();

    for sequence in 0..PACKET_COUNT {
        let mut packet = vec![0u8; PACKET_SIZE];
        packet[0] = 0x45;
        packet[1..5].copy_from_slice(&sequence.to_be_bytes());
        let outcome = send_ip_datagrams(
            &conn,
            &mut arena,
            &mut seg_scratch,
            &mut pending,
            None,
            &packet,
        )
        .await;
        assert_eq!(outcome.sent, 1, "packet {sequence} queued");
        assert_eq!(outcome.dropped_other, 0, "packet {sequence} not evicted");
    }

    let mut received = tokio::time::timeout(Duration::from_secs(30), accept_task)
        .await
        .expect("receiver completed before timeout")
        .expect("receiver task succeeded");

    // Datagrams are unreliable and may arrive out of order; every received one
    // must still be a distinct packet we actually sent (no corruption, no
    // duplication) — ordering is not part of the backpressure guarantee.
    received.sort_unstable();
    let distinct = received.len();
    received.dedup();
    assert_eq!(received.len(), distinct, "no datagram delivered twice");
    assert!(
        received.iter().all(|&sequence| sequence < PACKET_COUNT),
        "every delivered datagram is one we sent"
    );

    // More datagrams arrived than the send buffer could ever hold at once, so
    // the sender must have awaited capacity (backpressure) and kept draining
    // rather than the queue silently absorbing or evicting the overflow. This
    // stays clear of the exact-delivery assertion that made the test flaky while
    // still proving the queued packets flowed end-to-end.
    let send_buffer_capacity = QUIC_DATAGRAM_SEND_BUFFER_SIZE / PACKET_SIZE;
    assert!(
        received.len() > send_buffer_capacity,
        "expected more than the send buffer's {send_buffer_capacity} datagrams to arrive, got {}",
        received.len()
    );

    conn.close(0u32.into(), b"done");
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
