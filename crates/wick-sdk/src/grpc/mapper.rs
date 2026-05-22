//! Proto → domain conversions.
//!
//! Each server response is validated here: payment-hash lengths, status
//! strings, optional fields. Validation failures become
//! [`Error::InvalidResponse`] so callers can distinguish a malformed server
//! reply from an authentication or transport error.

use wick_proto::wick as pb;

use crate::error::{Error, Result};
use crate::types::{
    Balance, ChannelSummary, CreateTenantOutcome, JitInvoice, JitQuote, LspInfo, NodeInfo,
    PaymentRecord, PaymentResult, PaymentStatus, ReceiveInvoice,
};

pub(crate) fn parse_payment_hash(raw: &[u8]) -> Result<[u8; 32]> {
    let len = raw.len();
    <[u8; 32]>::try_from(raw)
        .map_err(|_| Error::InvalidResponse(format!("payment_hash must be 32 bytes, got {len}")))
}

impl From<pb::CreateTenantResponse> for CreateTenantOutcome {
    fn from(r: pb::CreateTenantResponse) -> Self {
        Self {
            tenant_id: r.tenant_id,
            api_token: r.api_token,
            macaroon: r.macaroon,
        }
    }
}

impl From<pb::GetBalanceResponse> for Balance {
    fn from(r: pb::GetBalanceResponse) -> Self {
        Self {
            lightning_msat: r.lightning_balance_msat,
            onchain_sats: r.onchain_balance_sats,
        }
    }
}

impl TryFrom<pb::SendPaymentResponse> for PaymentResult {
    type Error = Error;

    fn try_from(r: pb::SendPaymentResponse) -> Result<Self> {
        Ok(Self {
            payment_hash: parse_payment_hash(&r.payment_hash)?,
            fee_paid_msat: r.fee_paid_msat,
            status: PaymentStatus::from_wire(&r.status),
        })
    }
}

impl TryFrom<pb::ReceivePaymentResponse> for ReceiveInvoice {
    type Error = Error;

    fn try_from(r: pb::ReceivePaymentResponse) -> Result<Self> {
        Ok(Self {
            bolt11: r.bolt11,
            payment_hash: parse_payment_hash(&r.payment_hash)?,
        })
    }
}

impl TryFrom<pb::Payment> for PaymentRecord {
    type Error = Error;

    fn try_from(p: pb::Payment) -> Result<Self> {
        Ok(Self {
            payment_hash: parse_payment_hash(&p.payment_hash)?,
            is_outbound: p.is_outbound,
            amount_msat: p.amount_msat,
            fee_msat: p.fee_msat,
            status: PaymentStatus::from_wire(&p.status),
            timestamp: p.timestamp,
            memo: p.memo,
        })
    }
}

fn parse_pubkey_hex(hex_str: &str, field: &str) -> Result<bitcoin::secp256k1::PublicKey> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::InvalidResponse(format!("{field} not valid hex: {e}")))?;
    bitcoin::secp256k1::PublicKey::from_slice(&bytes)
        .map_err(|e| Error::InvalidResponse(format!("{field} not a valid secp256k1 key: {e}")))
}

impl TryFrom<pb::GetNodeInfoResponse> for NodeInfo {
    type Error = Error;

    fn try_from(r: pb::GetNodeInfoResponse) -> Result<Self> {
        let pubkey = parse_pubkey_hex(&r.node_id_hex, "node_id_hex")?;
        let port = u16::try_from(r.listen_port).map_err(|_| {
            Error::InvalidResponse(format!("listen_port {} exceeds u16", r.listen_port))
        })?;
        Ok(Self {
            pubkey,
            host: r.listen_host,
            port,
        })
    }
}

impl TryFrom<pb::ChannelSummary> for ChannelSummary {
    type Error = Error;

    fn try_from(c: pb::ChannelSummary) -> Result<Self> {
        let channel_id_len = c.channel_id.len();
        let channel_id = <[u8; 32]>::try_from(c.channel_id.as_slice()).map_err(|_| {
            Error::InvalidResponse(format!("channel_id must be 32 bytes, got {channel_id_len}"))
        })?;
        let counterparty = parse_pubkey_hex(&c.counterparty_pubkey_hex, "counterparty_pubkey_hex")?;
        Ok(Self {
            channel_id,
            counterparty,
            capacity_sat: c.capacity_sat,
            outbound_capacity_msat: c.outbound_capacity_msat,
            inbound_capacity_msat: c.inbound_capacity_msat,
            is_usable: c.is_usable,
        })
    }
}

impl TryFrom<pb::GetLspInfoResponse> for LspInfo {
    type Error = Error;

    fn try_from(r: pb::GetLspInfoResponse) -> Result<Self> {
        let pubkey = if r.lsp_pubkey_hex.is_empty() {
            None
        } else {
            Some(parse_pubkey_hex(&r.lsp_pubkey_hex, "lsp_pubkey_hex")?)
        };
        Ok(Self {
            pubkey,
            address: r.lsp_address,
            ready: r.ready,
        })
    }
}

impl TryFrom<pb::Lsps2GetInfoResponse> for JitQuote {
    type Error = Error;

    fn try_from(r: pb::Lsps2GetInfoResponse) -> Result<Self> {
        Ok(Self {
            lsp_pubkey: parse_pubkey_hex(&r.lsp_pubkey_hex, "lsp_pubkey_hex")?,
            min_fee_msat: r.min_fee_msat,
            proportional_ppm: r.proportional_ppm,
            min_payment_size_msat: r.min_payment_size_msat,
            max_payment_size_msat: r.max_payment_size_msat,
            valid_until_unix: r.valid_until_unix,
        })
    }
}

impl TryFrom<pb::GetJitInvoiceResponse> for JitInvoice {
    type Error = Error;

    fn try_from(r: pb::GetJitInvoiceResponse) -> Result<Self> {
        Ok(Self {
            bolt11: r.bolt11,
            payment_hash: parse_payment_hash(&r.payment_hash)?,
            jit_fee_msat_quote: r.jit_fee_msat_quote,
            lsp_pubkey: parse_pubkey_hex(&r.lsp_pubkey_hex, "lsp_pubkey_hex")?,
        })
    }
}
