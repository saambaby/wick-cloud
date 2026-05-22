//! Phase-4 Slice B smoke test for the wick-relay dumb pipe.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::implicit_clone,
    clippy::match_wild_err_arm,
    clippy::unnested_or_patterns
)]

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use wick_relay::{run, RelayConfig};

async fn spawn_relay(rate_per_min: u32) -> SocketAddr {
    let cfg = RelayConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        rate_per_min,
    };
    let (addr, _h) = run(cfg).await.expect("relay starts");
    // leak the handle: the test process tears down on exit
    addr
}

async fn connect(addr: SocketAddr, query: &str) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{addr}/?{query}");
    let (ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");
    ws
}

#[tokio::test]
async fn pair_and_forward_1kb() {
    let addr = spawn_relay(1000).await;

    // Initiator connects first; receives 16-byte stream id as first frame.
    let mut init = connect(addr, "role=initiator").await;
    let id_msg = tokio::time::timeout(Duration::from_secs(2), init.next())
        .await
        .expect("got stream id in time")
        .expect("frame present")
        .expect("ok frame");
    let id_bytes: Vec<u8> = match id_msg {
        Message::Binary(b) => b.to_vec(),
        other => panic!("expected binary stream-id frame, got {other:?}"),
    };
    assert_eq!(id_bytes.len(), 16, "stream id must be 16 bytes");
    let id_hex = hex::encode(&id_bytes);

    // Responder joins by stream id.
    let mut resp = connect(addr, &format!("role=responder&stream_id={id_hex}")).await;

    // Initiator → responder: 1 KB blob.
    let payload = vec![0xABu8; 1024];
    init.send(Message::Binary(payload.clone()))
        .await
        .expect("send 1kb");
    let recv = tokio::time::timeout(Duration::from_secs(2), resp.next())
        .await
        .expect("timely")
        .expect("frame")
        .expect("ok");
    match recv {
        Message::Binary(b) => {
            let got: Vec<u8> = b.to_vec();
            assert_eq!(got, payload);
        }
        other => panic!("expected binary, got {other:?}"),
    }
}

#[tokio::test]
async fn oversize_frame_rejected() {
    let addr = spawn_relay(1000).await;

    let mut init = connect(addr, "role=initiator").await;
    let id_msg = init.next().await.unwrap().unwrap();
    let id_bytes: Vec<u8> = match id_msg {
        Message::Binary(b) => b.to_vec(),
        other => panic!("got {other:?}"),
    };
    let id_hex = hex::encode(&id_bytes);
    let mut resp = connect(addr, &format!("role=responder&stream_id={id_hex}")).await;

    // 100 KB — over MAX_FRAME_BYTES (65_535). The relay should close the
    // pair rather than forward it.
    let payload = vec![0x42u8; 100 * 1024];
    let _ = init.send(Message::Binary(payload)).await;

    // The responder side should either get a Close or an Err before any
    // 100 KB binary payload arrives.
    let got = tokio::time::timeout(Duration::from_secs(3), resp.next()).await;
    match got {
        Ok(Some(Ok(Message::Binary(b)))) => {
            assert!(
                b.len() <= 65_535,
                "relay forwarded oversize frame ({} bytes)",
                b.len()
            );
        }
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
            // expected — pair was torn down
        }
        Ok(Some(Ok(other))) => panic!("unexpected message: {other:?}"),
        Err(_) => panic!("responder did not observe relay tear-down in time"),
    }
}

#[tokio::test]
async fn rate_limit_429() {
    let addr = spawn_relay(30).await;

    // 30 should succeed (we keep them open so they don't churn the limiter
    // — but the limiter is connect-based, so open/close behavior doesn't
    // matter as long as we don't cross the 60s window).
    let mut keep_alive = Vec::new();
    for i in 0..30 {
        let ws = connect(addr, "role=initiator").await;
        keep_alive.push(ws);
        // Read the stream-id frame so the per-conn handshake completes.
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            keep_alive.last_mut().unwrap().next(),
        )
        .await
        .unwrap_or_else(|_| panic!("conn {i} hung"));
    }

    // 31st should fail. tokio-tungstenite surfaces a 429 as an HTTP error
    // during the upgrade.
    let url = format!("ws://{addr}/?role=initiator");
    let result = tokio_tungstenite::connect_async(&url).await;
    assert!(
        result.is_err(),
        "31st connection should be rate-limited, got Ok"
    );
}
