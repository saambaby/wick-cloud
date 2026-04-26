//! Typed async VLS RPC wrappers over [`crate::SignerConnection`].
//!
//! Each function builds a VLS binary request message, dispatches it through
//! the current signer connection, and decodes the binary reply. All types
//! crossing the public boundary are plain Rust primitives (byte arrays,
//! integers) so the rest of `wick-vls` stays free of `vls-protocol` types.
//!
//! # Wire format for VLS bytes
//!
//! `[u16 type BE][data]` — the output of [`vls_protocol::msgs::SerBolt::as_vec`]
//! and the input of [`vls_protocol::msgs::DeBolt::from_vec`].

use std::time::Duration;

use anyhow::anyhow;
use bitcoin::hashes::Hash as _;
use bitcoin::psbt::Psbt as BitcoinPsbt;
use bitcoin::{Network, Txid};
use serde_bolt::{Array, ArrayBE, Octets, WireString};
use vls_protocol::model::{
    BitcoinSignature, DisclosedSecret, Htlc, PubKey, Sha256, Signature, Utxo,
};
use vls_protocol::msgs::{self, DeBolt, SerBolt};

use crate::connection::SignerConnection;

const VLS_TIMEOUT: Duration = Duration::from_secs(10);

/// LDK commitment numbers count down from this value (BOLT-3); VLS uses the complement.
const LDK_INITIAL_COMMITMENT_NUMBER: u64 = (1u64 << 48) - 1;

#[inline]
fn ldk_commitment_number_to_vls(ldk_commitment_number: u64) -> u64 {
    LDK_INITIAL_COMMITMENT_NUMBER - ldk_commitment_number
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

async fn node_call<Req, Rep>(conn: &SignerConnection, msg: Req) -> anyhow::Result<Rep>
where
    Req: SerBolt,
    Rep: DeBolt,
{
    let request_bytes = msg.as_vec();
    let reply_bytes = conn.dispatch_node_call(request_bytes, VLS_TIMEOUT).await?;
    Rep::from_vec(reply_bytes).map_err(|e| anyhow!("VLS node reply decode: {:?}", e))
}

async fn channel_call<Req, Rep>(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    msg: Req,
) -> anyhow::Result<Rep>
where
    Req: SerBolt,
    Rep: DeBolt,
{
    let request_bytes = msg.as_vec();
    let reply_bytes = conn
        .dispatch_channel_call(dbid, peer_id, request_bytes, VLS_TIMEOUT)
        .await?;
    Rep::from_vec(reply_bytes).map_err(|e| anyhow!("VLS channel reply decode: {:?}", e))
}

// ── Init / identity ───────────────────────────────────────────────────────────

/// `HsmdInit2`: LDK-style signer init. Returns `(node_pubkey_33, bip32_extended_78)`.
pub async fn rpc_hsmd_init2(
    conn: &SignerConnection,
    network: Network,
) -> anyhow::Result<([u8; 33], [u8; 78])> {
    let network_name = match network {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        _ => "regtest",
    };
    let reply: msgs::HsmdInit2Reply = node_call(
        conn,
        msgs::HsmdInit2 {
            derivation_style: 1, // LDK style
            network_name: WireString(network_name.as_bytes().to_vec()),
            dev_seed: None,
            dev_allowlist: Array(vec![]),
        },
    )
    .await?;
    Ok((reply.node_id.0, reply.bip32.0))
}

// ── Wick extension RPCs (custom message types 0xFD01 – 0xFD05) ────────────────

#[derive(Debug, Clone)]
pub struct LdkNodeKeysResult {
    pub peer_storage_key: [u8; 32],
    pub inbound_payment_key: [u8; 32],
    pub receive_auth_key: [u8; 32],
}

/// Fetch the three LDK-only node keys (peer-storage, inbound-payment, receive-auth)
/// derived in the SDK from the master seed via domain-separated HKDF.
///
/// Wire — request:  `[0xFD01 BE][u8 version=1]`
/// Wire — response: `[32B][32B][32B]`
pub async fn rpc_get_ldk_node_keys(conn: &SignerConnection) -> anyhow::Result<LdkNodeKeysResult> {
    const TYPE_BE: [u8; 2] = 0xFD01u16.to_be_bytes();
    const VERSION: u8 = 1;
    let request = [TYPE_BE[0], TYPE_BE[1], VERSION].to_vec();
    let reply_bytes = conn.dispatch_node_call(request, VLS_TIMEOUT).await?;
    if reply_bytes.len() != 96 {
        anyhow::bail!(
            "rpc_get_ldk_node_keys: expected 96B reply, got {}B",
            reply_bytes.len()
        );
    }
    let mut peer_storage_key = [0u8; 32];
    let mut inbound_payment_key = [0u8; 32];
    let mut receive_auth_key = [0u8; 32];
    peer_storage_key.copy_from_slice(&reply_bytes[0..32]);
    inbound_payment_key.copy_from_slice(&reply_bytes[32..64]);
    receive_auth_key.copy_from_slice(&reply_bytes[64..96]);
    Ok(LdkNodeKeysResult {
        peer_storage_key,
        inbound_payment_key,
        receive_auth_key,
    })
}

/// Wire — request: `[0xFD02 BE][u8 version=1][u16 BE key_len][key_bytes][plaintext]`
pub async fn rpc_vss_encrypt(
    conn: &SignerConnection,
    store_key: &str,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    const VERSION: u8 = 1;
    let mut request = Vec::with_capacity(2 + 1 + 2 + store_key.len() + plaintext.len());
    request.extend_from_slice(&0xFD02u16.to_be_bytes());
    request.push(VERSION);
    request.extend_from_slice(
        &u16::try_from(store_key.len())
            .map_err(|_| anyhow!("store_key too long"))?
            .to_be_bytes(),
    );
    request.extend_from_slice(store_key.as_bytes());
    request.extend_from_slice(plaintext);
    conn.dispatch_node_call(request, VLS_TIMEOUT).await
}

/// Wire — request: `[0xFD03 BE][u8 version=1][u16 BE key_len][key_bytes][ciphertext]`
pub async fn rpc_vss_decrypt(
    conn: &SignerConnection,
    store_key: &str,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    const VERSION: u8 = 1;
    let mut request = Vec::with_capacity(2 + 1 + 2 + store_key.len() + ciphertext.len());
    request.extend_from_slice(&0xFD03u16.to_be_bytes());
    request.push(VERSION);
    request.extend_from_slice(
        &u16::try_from(store_key.len())
            .map_err(|_| anyhow!("store_key too long"))?
            .to_be_bytes(),
    );
    request.extend_from_slice(store_key.as_bytes());
    request.extend_from_slice(ciphertext);
    conn.dispatch_node_call(request, VLS_TIMEOUT).await
}

// ── NodeSigner operations ─────────────────────────────────────────────────────

pub async fn rpc_ecdh(conn: &SignerConnection, point: [u8; 33]) -> anyhow::Result<[u8; 32]> {
    let reply: msgs::EcdhReply = node_call(
        conn,
        msgs::Ecdh {
            point: PubKey(point),
        },
    )
    .await?;
    Ok(reply.secret.0)
}

pub async fn rpc_sign_invoice(
    conn: &SignerConnection,
    u5bytes: Vec<u8>,
    hrp: Vec<u8>,
) -> anyhow::Result<[u8; 65]> {
    let reply: msgs::SignInvoiceReply = node_call(
        conn,
        msgs::SignInvoice {
            u5bytes: Octets(u5bytes),
            hrp: Octets(hrp),
        },
    )
    .await?;
    Ok(reply.signature.0)
}

pub async fn rpc_sign_gossip_message(
    conn: &SignerConnection,
    message: Vec<u8>,
) -> anyhow::Result<[u8; 64]> {
    let reply: msgs::SignGossipMessageReply = node_call(
        conn,
        msgs::SignGossipMessage {
            message: Octets(message),
        },
    )
    .await?;
    Ok(reply.signature.0)
}

/// Try `SignBolt12V2` first; fall back to `SignBolt12` for older signer runtimes.
pub async fn rpc_sign_bolt12_invoice(
    conn: &SignerConnection,
    merkle_root: [u8; 32],
) -> anyhow::Result<[u8; 64]> {
    let message_name = WireString(b"invoice".to_vec());
    let field_name = WireString(b"signature".to_vec());

    let v2 = node_call::<msgs::SignBolt12V2, msgs::SignBolt12V2Reply>(
        conn,
        msgs::SignBolt12V2 {
            message_name: message_name.clone(),
            field_name: field_name.clone(),
            merkle_root: Sha256(merkle_root),
            info: Octets(vec![]),
            public_tweak: Octets(vec![]),
        },
    )
    .await;
    if let Ok(reply) = v2 {
        return Ok(reply.signature.0);
    }

    let reply: msgs::SignBolt12Reply = node_call(
        conn,
        msgs::SignBolt12 {
            message_name,
            field_name,
            merkle_root: Sha256(merkle_root),
            public_tweak: Octets(vec![]),
        },
    )
    .await?;
    Ok(reply.signature.0)
}

// ── SignerProvider operations ─────────────────────────────────────────────────

pub struct ChannelBasepointsResult {
    pub revocation: [u8; 33],
    pub payment: [u8; 33],
    pub htlc: [u8; 33],
    pub delayed_payment: [u8; 33],
    pub funding: [u8; 33],
}

pub async fn rpc_get_channel_basepoints(
    conn: &SignerConnection,
    routing_peer_id: [u8; 33],
    dbid: u64,
) -> anyhow::Result<ChannelBasepointsResult> {
    let reply: msgs::GetChannelBasepointsReply = node_call(
        conn,
        msgs::GetChannelBasepoints {
            node_id: PubKey(routing_peer_id),
            dbid,
        },
    )
    .await?;
    Ok(ChannelBasepointsResult {
        revocation: reply.basepoints.revocation.0,
        payment: reply.basepoints.payment.0,
        htlc: reply.basepoints.htlc.0,
        delayed_payment: reply.basepoints.delayed_payment.0,
        funding: reply.funding.0,
    })
}

// ── ChannelSigner operations ──────────────────────────────────────────────────

pub async fn rpc_get_per_commitment_point(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    idx: u64,
) -> anyhow::Result<[u8; 33]> {
    let reply: msgs::GetPerCommitmentPoint2Reply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::GetPerCommitmentPoint2 {
            commitment_number: ldk_commitment_number_to_vls(idx),
        },
    )
    .await?;
    Ok(reply.point.0)
}

pub async fn rpc_release_commitment_secret(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    idx: u64,
) -> anyhow::Result<[u8; 32]> {
    let reply: msgs::RevokeCommitmentTxReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::RevokeCommitmentTx {
            commitment_number: ldk_commitment_number_to_vls(idx),
        },
    )
    .await?;
    Ok(reply.old_commitment_secret.0)
}

pub async fn rpc_validate_counterparty_revocation(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    idx: u64,
    secret: [u8; 32],
) -> anyhow::Result<()> {
    let _reply: msgs::ValidateRevocationReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::ValidateRevocation {
            commitment_number: ldk_commitment_number_to_vls(idx),
            commitment_secret: DisclosedSecret(secret),
        },
    )
    .await?;
    Ok(())
}

// ── EcdsaChannelSigner operations ─────────────────────────────────────────────

/// `(side, amount_msat, payment_hash_32, cltv_expiry)` — `side` 0 = local outbound, 1 = remote inbound.
pub type HtlcEntry = (u8, u64, [u8; 32], u32);

#[allow(clippy::too_many_arguments)]
pub async fn rpc_sign_remote_commitment(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    remote_per_commitment_point: [u8; 33],
    commitment_number: u64,
    feerate: u32,
    to_local_value_sat: u64,
    to_remote_value_sat: u64,
    htlcs: Vec<HtlcEntry>,
) -> anyhow::Result<([u8; 64], Vec<[u8; 64]>)> {
    let vls_htlcs = build_htlcs(htlcs);
    let reply: msgs::SignCommitmentTxWithHtlcsReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::SignRemoteCommitmentTx2 {
            remote_per_commitment_point: PubKey(remote_per_commitment_point),
            commitment_number: ldk_commitment_number_to_vls(commitment_number),
            feerate,
            to_local_value_sat,
            to_remote_value_sat,
            htlcs: Array(vls_htlcs),
        },
    )
    .await?;
    let commitment_sig = reply.signature.signature.0;
    let htlc_sigs = reply
        .htlc_signatures
        .0
        .iter()
        .map(|s| s.signature.0)
        .collect();
    Ok((commitment_sig, htlc_sigs))
}

pub async fn rpc_sign_holder_commitment(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    commitment_number: u64,
) -> anyhow::Result<[u8; 64]> {
    let reply: msgs::SignCommitmentTxWithHtlcsReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::SignLocalCommitmentTx2 {
            commitment_number: ldk_commitment_number_to_vls(commitment_number),
        },
    )
    .await?;
    Ok(reply.signature.signature.0)
}

#[allow(clippy::too_many_arguments)]
pub async fn rpc_sign_closing_tx(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    to_local_value_sat: u64,
    to_remote_value_sat: u64,
    local_script: Vec<u8>,
    remote_script: Vec<u8>,
) -> anyhow::Result<[u8; 64]> {
    let reply: msgs::SignTxReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::SignMutualCloseTx2 {
            to_local_value_sat,
            to_remote_value_sat,
            local_script: Octets(local_script),
            remote_script: Octets(remote_script),
            // index 1 = wallet_xpub/1 = deposit address; matches get_shutdown_scriptpubkey.
            // VLS validates via can_spend([1], script).
            local_wallet_path_hint: ArrayBE(vec![1]),
        },
    )
    .await?;
    Ok(reply.signature.signature.0)
}

/// Returns `Ok(Some(secret))` for VLS protocol v4 (revocation inline);
/// `Ok(None)` for v5+ (explicit `RevokeCommitmentTx` follows).
#[allow(clippy::too_many_arguments)]
pub async fn rpc_validate_holder_commitment(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    commitment_number: u64,
    feerate: u32,
    to_local_value_sat: u64,
    to_remote_value_sat: u64,
    htlcs: Vec<HtlcEntry>,
    commitment_sig: [u8; 64],
    htlc_sigs: Vec<[u8; 64]>,
) -> anyhow::Result<Option<[u8; 32]>> {
    let vls_htlcs = build_htlcs(htlcs);
    let vls_htlc_sigs = htlc_sigs
        .into_iter()
        .map(|s| BitcoinSignature {
            signature: Signature(s),
            sighash: 0x01,
        })
        .collect::<Vec<_>>();
    let reply: msgs::ValidateCommitmentTxReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::ValidateCommitmentTx2 {
            commitment_number: ldk_commitment_number_to_vls(commitment_number),
            feerate,
            to_local_value_sat,
            to_remote_value_sat,
            htlcs: Array(vls_htlcs),
            signature: BitcoinSignature {
                signature: Signature(commitment_sig),
                sighash: 0x01,
            },
            htlc_signatures: Array(vls_htlc_sigs),
        },
    )
    .await?;
    Ok(reply.old_commitment_secret.map(|ds| ds.0))
}

pub async fn rpc_setup_channel(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    setup: msgs::SetupChannel,
) -> anyhow::Result<()> {
    let _reply: msgs::SetupChannelReply = channel_call(conn, dbid, peer_id, setup).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn rpc_setup_channel_from_primitives(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    is_outbound: bool,
    channel_value: u64,
    push_value: u64,
    funding_txid: Txid,
    funding_txout: u16,
    to_self_delay: u16,
    local_shutdown_script: Vec<u8>,
    local_shutdown_wallet_index: Option<u32>,
    remote_revocation_basepoint: [u8; 33],
    remote_payment_point: [u8; 33],
    remote_htlc_basepoint: [u8; 33],
    remote_delayed_payment_basepoint: [u8; 33],
    remote_funding_pubkey: [u8; 33],
    remote_to_self_delay: u16,
    remote_shutdown_script: Vec<u8>,
    channel_type: Vec<u8>,
) -> anyhow::Result<()> {
    rpc_setup_channel(
        conn,
        dbid,
        peer_id,
        msgs::SetupChannel {
            is_outbound,
            channel_value,
            push_value,
            funding_txid,
            funding_txout,
            to_self_delay,
            local_shutdown_script: Octets(local_shutdown_script),
            local_shutdown_wallet_index,
            remote_basepoints: vls_protocol::model::Basepoints {
                revocation: PubKey(remote_revocation_basepoint),
                payment: PubKey(remote_payment_point),
                htlc: PubKey(remote_htlc_basepoint),
                delayed_payment: PubKey(remote_delayed_payment_basepoint),
            },
            remote_funding_pubkey: PubKey(remote_funding_pubkey),
            remote_to_self_delay,
            remote_shutdown_script: Octets(remote_shutdown_script),
            channel_type: Octets(channel_type),
        },
    )
    .await
}

/// Wick extension `0xFD05`: ask the SDK for a wallet address at the given BIP32 index.
///
/// Wire — request:  `[0xFD05 BE][u8 version=1][u32 LE index]`
/// Wire — response: `[u16 LE addr_len][addr_bytes][script_pubkey]`
pub async fn rpc_get_wallet_address(
    conn: &SignerConnection,
    index: u32,
) -> anyhow::Result<(String, Vec<u8>)> {
    const TYPE_BE: [u8; 2] = 0xFD05u16.to_be_bytes();
    const VERSION: u8 = 1;
    let mut request = Vec::with_capacity(2 + 1 + 4);
    request.extend_from_slice(&TYPE_BE);
    request.push(VERSION);
    request.extend_from_slice(&index.to_le_bytes());

    let reply = conn.dispatch_node_call(request, VLS_TIMEOUT).await?;
    if reply.len() < 2 {
        anyhow::bail!("rpc_get_wallet_address: reply too short ({}B)", reply.len());
    }
    let addr_len = u16::from_le_bytes([reply[0], reply[1]]) as usize;
    if reply.len() < 2 + addr_len {
        anyhow::bail!(
            "rpc_get_wallet_address: expected {}B for address, got {}B",
            2 + addr_len,
            reply.len()
        );
    }
    let address = String::from_utf8(reply[2..2 + addr_len].to_vec())
        .map_err(|e| anyhow::anyhow!("rpc_get_wallet_address: invalid UTF-8 address: {e}"))?;
    let script_pubkey = reply[2 + addr_len..].to_vec();
    Ok((address, script_pubkey))
}

/// Wick extension `0xFD04`: derive a fresh splice funding pubkey from the parent funding txid.
///
/// Wire — request:  `[0xFD04 BE][u8 version=1][txid:32]`
/// Wire — response: `[pubkey:33]`
pub async fn rpc_get_splice_new_funding_pubkey(
    conn: &SignerConnection,
    splice_parent_funding_txid: Txid,
) -> anyhow::Result<[u8; 33]> {
    const TYPE_BE: [u8; 2] = 0xFD04u16.to_be_bytes();
    const VERSION: u8 = 1;
    let mut request = Vec::with_capacity(2 + 1 + 32);
    request.extend_from_slice(&TYPE_BE);
    request.push(VERSION);
    request.extend_from_slice(&splice_parent_funding_txid.to_byte_array());

    let reply = conn.dispatch_node_call(request, VLS_TIMEOUT).await?;
    if reply.len() != 33 {
        anyhow::bail!(
            "rpc_get_splice_new_funding_pubkey: expected 33B reply, got {}B",
            reply.len()
        );
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&reply);
    Ok(out)
}

pub async fn rpc_sign_channel_announcement(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    announcement: Vec<u8>,
) -> anyhow::Result<[u8; 64]> {
    let reply: msgs::SignChannelAnnouncementReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::SignChannelAnnouncement {
            announcement: Octets(announcement),
        },
    )
    .await?;
    Ok(reply.node_signature.0)
}

// ── Wallet / on-chain signing ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WithdrawalUtxo {
    pub txid: Txid,
    pub outnum: u32,
    pub amount_sat: u64,
    pub keyindex: u32,
    pub is_p2sh: bool,
    pub script_pubkey: Vec<u8>,
    pub is_in_coinbase: bool,
}

pub async fn rpc_sign_withdrawal(
    conn: &SignerConnection,
    psbt_bytes: Vec<u8>,
    utxos: Vec<WithdrawalUtxo>,
) -> anyhow::Result<Vec<u8>> {
    use serde_bolt::WithSize;
    use vls_protocol::psbt::StreamedPSBT;

    let psbt =
        BitcoinPsbt::deserialize(&psbt_bytes).map_err(|e| anyhow!("PSBT deserialize: {e}"))?;
    let streamed = StreamedPSBT::new(psbt);
    let utxos = Array(
        utxos
            .into_iter()
            .map(|u| Utxo {
                txid: u.txid,
                outnum: u.outnum,
                amount: u.amount_sat,
                keyindex: u.keyindex,
                is_p2sh: u.is_p2sh,
                script: Octets(u.script_pubkey),
                close_info: None,
                is_in_coinbase: u.is_in_coinbase,
            })
            .collect(),
    );

    let reply: msgs::SignWithdrawalReply = node_call(
        conn,
        msgs::SignWithdrawal {
            utxos,
            psbt: WithSize(streamed),
        },
    )
    .await?;
    Ok(reply.psbt.0.inner.serialize())
}

// ── HTLC / penalty / anchor signing ───────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn rpc_sign_local_htlc_tx2(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    tx: bitcoin::Transaction,
    input: u32,
    per_commitment_number: u64,
    offered: bool,
    cltv_expiry: u32,
    htlc_amount_msat: u64,
    payment_hash: [u8; 32],
) -> anyhow::Result<[u8; 64]> {
    let reply: msgs::SignTxReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::SignLocalHtlcTx2 {
            tx: serde_bolt::WithSize(tx),
            input,
            per_commitment_number: ldk_commitment_number_to_vls(per_commitment_number),
            offered,
            cltv_expiry,
            htlc_amount_msat,
            payment_hash: Sha256(payment_hash),
        },
    )
    .await?;
    Ok(reply.signature.signature.0)
}

#[allow(clippy::too_many_arguments)]
pub async fn rpc_sign_remote_htlc_tx(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    tx: bitcoin::Transaction,
    psbt_bytes: Vec<u8>,
    wscript: Vec<u8>,
    remote_per_commitment_point: [u8; 33],
    option_anchors: bool,
) -> anyhow::Result<[u8; 64]> {
    let psbt =
        BitcoinPsbt::deserialize(&psbt_bytes).map_err(|e| anyhow!("PSBT deserialize: {e}"))?;
    let reply: msgs::SignTxReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::SignRemoteHtlcTx {
            tx: serde_bolt::WithSize(tx),
            psbt: serde_bolt::WithSize(vls_protocol::psbt::PsbtWrapper { inner: psbt }),
            wscript: Octets(wscript),
            remote_per_commitment_point: PubKey(remote_per_commitment_point),
            option_anchors,
        },
    )
    .await?;
    Ok(reply.signature.signature.0)
}

pub async fn rpc_sign_penalty_to_us(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    revocation_secret: [u8; 32],
    tx: bitcoin::Transaction,
    psbt_bytes: Vec<u8>,
    wscript: Vec<u8>,
) -> anyhow::Result<[u8; 64]> {
    let psbt =
        BitcoinPsbt::deserialize(&psbt_bytes).map_err(|e| anyhow!("PSBT deserialize: {e}"))?;
    let reply: msgs::SignTxReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::SignPenaltyToUs {
            revocation_secret: DisclosedSecret(revocation_secret),
            tx: serde_bolt::WithSize(tx),
            psbt: serde_bolt::WithSize(vls_protocol::psbt::PsbtWrapper { inner: psbt }),
            wscript: Octets(wscript),
        },
    )
    .await?;
    Ok(reply.signature.signature.0)
}

#[derive(Debug, Clone)]
pub struct AnchorUtxo {
    pub txid: Txid,
    pub outnum: u32,
    pub amount_sat: u64,
    pub keyindex: u32,
    pub is_p2sh: bool,
    pub script_pubkey: Vec<u8>,
    pub is_in_coinbase: bool,
}

pub async fn rpc_sign_anchorspend(
    conn: &SignerConnection,
    peer_id: [u8; 33],
    dbid: u64,
    psbt_bytes: Vec<u8>,
    utxos: Vec<AnchorUtxo>,
) -> anyhow::Result<Vec<u8>> {
    use serde_bolt::WithSize;
    use vls_protocol::psbt::StreamedPSBT;

    let psbt =
        BitcoinPsbt::deserialize(&psbt_bytes).map_err(|e| anyhow!("PSBT deserialize: {e}"))?;
    let streamed = StreamedPSBT::new(psbt);
    let utxos = utxos
        .into_iter()
        .map(|u| Utxo {
            txid: u.txid,
            outnum: u.outnum,
            amount: u.amount_sat,
            keyindex: u.keyindex,
            is_p2sh: u.is_p2sh,
            script: Octets(u.script_pubkey),
            close_info: None,
            is_in_coinbase: u.is_in_coinbase,
        })
        .collect::<Vec<_>>();
    let reply: msgs::SignAnchorspendReply = node_call(
        conn,
        msgs::SignAnchorspend {
            peer_id: PubKey(peer_id),
            dbid,
            utxos: Array(utxos),
            psbt: WithSize(streamed),
        },
    )
    .await?;
    Ok(reply.psbt.0.inner.serialize())
}

pub async fn rpc_sign_splice_tx(
    conn: &SignerConnection,
    dbid: u64,
    peer_id: [u8; 33],
    tx: bitcoin::Transaction,
    psbt_bytes: Vec<u8>,
    remote_funding_key: [u8; 33],
    input_index: u32,
) -> anyhow::Result<[u8; 64]> {
    let psbt =
        BitcoinPsbt::deserialize(&psbt_bytes).map_err(|e| anyhow!("PSBT deserialize: {e}"))?;
    let reply: msgs::SignTxReply = channel_call(
        conn,
        dbid,
        peer_id,
        msgs::SignSpliceTx {
            tx: serde_bolt::WithSize(tx),
            psbt: serde_bolt::WithSize(vls_protocol::psbt::PsbtWrapper { inner: psbt }),
            remote_funding_key: PubKey(remote_funding_key),
            input_index,
        },
    )
    .await?;
    Ok(reply.signature.signature.0)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn build_htlcs(htlcs: Vec<HtlcEntry>) -> Vec<Htlc> {
    htlcs
        .into_iter()
        .map(|(side, amount, hash, cltv)| Htlc {
            side,
            amount,
            payment_hash: Sha256(hash),
            ctlv_expiry: cltv,
        })
        .collect()
}
