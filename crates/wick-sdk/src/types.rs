//! Client-side domain types.
//!
//! These mirror the wire shapes in `wick_proto::wick` but are deliberately
//! independent of `wick-lightning`: depending on that crate would drag LDK
//! into every client build. Proto → domain conversion lives in
//! [`crate::grpc::mapper`].

/// Lightning + on-chain balance snapshot from the server.
///
/// On-chain here refers to the server-held on-chain balance used for
/// channel funding; the device's own on-chain wallet is tracked separately
/// via BDK in [`crate::WickClient::onchain_spendable_sat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Balance {
    /// Spendable Lightning balance in millisatoshis.
    pub lightning_msat: u64,
    /// Confirmed server-side on-chain balance in satoshis.
    pub onchain_sats: u64,
}

/// Status of a payment row.
///
/// Unknown status strings from the server map to [`PaymentStatus::Unknown`]
/// rather than an error — the wire field is a free-form string that new
/// server builds may extend. Treat `Unknown` as "not yet classifiable;
/// poll again".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    /// Payment has been enqueued; not yet settled.
    Pending,
    /// Payment settled successfully.
    Succeeded,
    /// Payment failed terminally.
    Failed,
    /// Server returned a status string the SDK did not recognise.
    Unknown,
}

impl PaymentStatus {
    /// Parse a wire status string. Unknown values return [`Self::Unknown`]
    /// (never an error).
    #[must_use]
    pub fn from_wire(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

/// Outcome of [`crate::WickClient::send_payment`].
///
/// `fee_paid_msat` is typically `0` on enqueue; the server's event handler
/// updates it once the payment settles. Poll [`crate::WickClient::transactions`]
/// for the final value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentResult {
    /// 32-byte BOLT11 payment hash.
    pub payment_hash: [u8; 32],
    /// Routing fee paid, in millisatoshis. `0` at enqueue.
    pub fee_paid_msat: u64,
    /// Current status.
    pub status: PaymentStatus,
}

/// A single payment history row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRecord {
    /// 32-byte payment hash.
    pub payment_hash: [u8; 32],
    /// `true` if this was an outbound (sent) payment; `false` for inbound.
    pub is_outbound: bool,
    /// Amount in millisatoshis.
    pub amount_msat: u64,
    /// Routing fee in millisatoshis. Always `0` for inbound.
    pub fee_msat: u64,
    /// Status at the time the record was read.
    pub status: PaymentStatus,
    /// Unix timestamp (seconds) when the payment was created.
    pub timestamp: i64,
    /// Optional invoice memo.
    pub memo: Option<String>,
}

/// Outcome of [`crate::WickClient::receive_payment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveInvoice {
    /// The BOLT11 invoice string.
    pub bolt11: String,
    /// 32-byte payment hash embedded in the invoice.
    pub payment_hash: [u8; 32],
}

/// Outcome of [`crate::WickClient::register`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTenantOutcome {
    /// Server-assigned tenant id (UUID string, stable across re-registrations
    /// with the same pubkey).
    pub tenant_id: String,
    /// Bearer token issued by the server — returned once, never re-issued.
    /// [`crate::WickClient`] stores it automatically; callers don't normally
    /// need to read this, but it's exposed for persistence across process
    /// restarts.
    pub api_token: String,
    /// Serialized macaroon issued by the server when its macaroon auth
    /// surface is wired. Empty when the server runs the legacy bearer-only
    /// path. [`crate::WickClient`] prefers this for wallet RPCs when
    /// non-empty (sent as `x-wick-macaroon: <base64>`); the bearer is
    /// retained for the signer-attach path.
    pub macaroon: Vec<u8>,
}

/// Tenant's server-side Lightning node pubkey + P2P listen address.
///
/// Returned by [`crate::WickClient::node_info`]. Required by other clients
/// who want to reach this tenant's node via
/// [`crate::WickClient::connect_peer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// 33-byte compressed secp256k1 pubkey of the tenant's LDK node.
    pub pubkey: bitcoin::secp256k1::PublicKey,
    /// Host the node's P2P listener bound to. Empty when no listener is
    /// active.
    pub host: String,
    /// Port the node's P2P listener bound to. Zero when no listener is
    /// active.
    pub port: u16,
}

/// Snapshot of a single Lightning channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSummary {
    /// 32-byte channel id.
    pub channel_id: [u8; 32],
    /// Counterparty's compressed secp256k1 pubkey.
    pub counterparty: bitcoin::secp256k1::PublicKey,
    /// Total channel capacity in satoshis.
    pub capacity_sat: u64,
    /// Local outbound capacity in millisatoshis.
    pub outbound_capacity_msat: u64,
    /// Remote balance available to receive in millisatoshis.
    pub inbound_capacity_msat: u64,
    /// `true` once the channel is funded, confirmed, and ready for
    /// payments.
    pub is_usable: bool,
}

/// Information about the in-process operator-mode LSP.
///
/// Returned by [`crate::WickClient::lsp_info`]. `pubkey` is `None` when
/// the server has no LSP enabled — JIT-related calls will fail in that
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspInfo {
    /// 33-byte compressed pubkey of the LSP node, or `None` when LSP is
    /// disabled on this server.
    pub pubkey: Option<bitcoin::secp256k1::PublicKey>,
    /// LSP `host:port` listen address. Empty string when LSP is disabled.
    pub address: String,
    /// `true` when the LSP daemon is connected to its upstream and has
    /// liquidity available.
    pub ready: bool,
}

/// LSPS2 fee quote returned by [`crate::WickClient::lsps2_get_info`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitQuote {
    /// LSP node pubkey that issued the quote.
    pub lsp_pubkey: bitcoin::secp256k1::PublicKey,
    /// Floor opening fee in millisatoshis.
    pub min_fee_msat: u64,
    /// Proportional fee in parts-per-million of the JIT payment size.
    pub proportional_ppm: u32,
    /// Minimum payment size (msat) the LSP will accept.
    pub min_payment_size_msat: u64,
    /// Maximum payment size (msat) the LSP will accept.
    pub max_payment_size_msat: u64,
    /// Quote expiry as Unix seconds. After this, the SDK must
    /// re-request before issuing an invoice.
    pub valid_until_unix: i64,
}

/// JIT-enabled BOLT11 invoice produced by
/// [`crate::WickClient::receive_payment_jit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitInvoice {
    /// BOLT11 invoice string carrying the LSP intercept SCID as a
    /// private route hint.
    pub bolt11: String,
    /// 32-byte payment hash embedded in the invoice.
    pub payment_hash: [u8; 32],
    /// Quoted opening fee (msat) the LSP will deduct from the first
    /// inbound payment routed against the intercept SCID.
    pub jit_fee_msat_quote: u64,
    /// 33-byte LSP pubkey that will open the JIT channel.
    pub lsp_pubkey: bitcoin::secp256k1::PublicKey,
}
