//! Pending-stream registry. An initiator parks a oneshot here keyed by a
//! server-minted stream ID; the matching responder consumes the oneshot,
//! and the two sockets are spliced together by [`crate::session`].

use dashmap::DashMap;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_tungstenite::WebSocketStream;

/// Wire max for a Noise frame (Noise spec §3, 16-bit length prefix).
/// We pass payloads opaque, but reject anything larger up front to
/// keep memory bounded.
pub const MAX_FRAME_BYTES: usize = 65_535;

/// One side of a not-yet-paired WebSocket.
pub type PendingSocket = WebSocketStream<TcpStream>;

/// In-memory map: stream-id → oneshot waiting for the responder socket.
/// The initiator owns the receive end; the responder calls
/// [`StreamRegistry::join_responder`] to hand off its socket.
#[derive(Debug)]
pub struct StreamRegistry {
    pending: DashMap<[u8; 16], oneshot::Sender<PendingSocket>>,
}

impl StreamRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
        }
    }

    /// Reserve a fresh server-minted stream-id and return both:
    /// - the 16-byte id (caller surfaces this to the initiator over the wire), and
    /// - a receiver that resolves with the responder's socket once it arrives.
    #[must_use]
    pub fn register_initiator(&self) -> ([u8; 16], oneshot::Receiver<PendingSocket>) {
        let mut id = [0u8; 16];
        loop {
            OsRng.fill_bytes(&mut id);
            if !self.pending.contains_key(&id) {
                break;
            }
        }
        let (tx, rx) = oneshot::channel::<PendingSocket>();
        self.pending.insert(id, tx);
        (id, rx)
    }

    /// Look up a pending initiator slot and complete it with the
    /// responder's socket. Returns `Err(socket)` if no such id is
    /// registered — caller should reject with a protocol error.
    ///
    /// The boxed `PendingSocket` keeps the error variant small enough
    /// to satisfy `clippy::result_large_err` while still letting the
    /// caller recover the unfederated socket.
    pub fn join_responder(
        &self,
        id: &[u8; 16],
        socket: PendingSocket,
    ) -> Result<(), Box<PendingSocket>> {
        match self.pending.remove(id) {
            Some((_, tx)) => tx.send(socket).map_err(Box::new),
            None => Err(Box::new(socket)),
        }
    }

    /// Cancel a pending initiator slot — called when the initiator's
    /// socket disconnects before a responder arrives.
    pub fn cancel(&self, id: &[u8; 16]) {
        let _ = self.pending.remove(id);
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}
