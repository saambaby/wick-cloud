//! Lightning gRPC client.
//!
//! Wraps the tonic-generated [`WalletServiceClient`] with a bearer-token
//! interceptor and converts every response into SDK domain types. Callers
//! don't use this directly — [`crate::WickClient`] composes it with
//! identity, wallet, and chain.

mod auth;
mod mapper;

use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint};
use wick_proto::wick as pb;
use wick_proto::wick::wallet_service_client::WalletServiceClient;

use auth::AuthInterceptor;
pub(crate) use auth::{empty_token, SharedToken};

use crate::error::{Error, Result};
use crate::types::{
    Balance, ChannelSummary, CreateTenantOutcome, JitInvoice, JitQuote, LspInfo, NodeInfo,
    PaymentRecord, PaymentResult, ReceiveInvoice,
};

/// Thin tonic client wrapper with an auth interceptor. Cheap to clone —
/// the underlying `Channel` is already `Arc`-backed.
#[derive(Debug, Clone)]
pub(crate) struct LightningClient {
    inner: WalletServiceClient<InterceptedService<Channel, AuthInterceptor>>,
}

impl LightningClient {
    /// Open a tonic channel to `endpoint` and attach the shared bearer
    /// token via an interceptor.
    pub(crate) async fn connect(endpoint: &str, token: SharedToken) -> Result<Self> {
        let ep = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|e| Error::Config(format!("invalid server_endpoint: {e}")))?;
        let channel = ep.connect().await?;
        let service = InterceptedService::new(channel, AuthInterceptor::new(token));
        let inner = WalletServiceClient::new(service);
        Ok(Self { inner })
    }

    pub(crate) async fn create_tenant(
        &self,
        pubkey_hex: &str,
        plan_tier: &str,
    ) -> Result<CreateTenantOutcome> {
        let mut client = self.inner.clone();
        let resp = client
            .create_tenant(pb::CreateTenantRequest {
                pubkey_hex: pubkey_hex.to_owned(),
                plan_tier: plan_tier.to_owned(),
            })
            .await?
            .into_inner();
        Ok(resp.into())
    }

    pub(crate) async fn get_balance(&self) -> Result<Balance> {
        let mut client = self.inner.clone();
        let resp = client
            .get_balance(pb::GetBalanceRequest { tenant_id: 0 })
            .await?
            .into_inner();
        Ok(resp.into())
    }

    pub(crate) async fn send_payment(&self, bolt11: &str) -> Result<PaymentResult> {
        if bolt11.is_empty() {
            return Err(Error::InvalidInput("bolt11 is empty".to_owned()));
        }
        let mut client = self.inner.clone();
        let resp = client
            .send_payment(pb::SendPaymentRequest {
                tenant_id: 0,
                bolt11: bolt11.to_owned(),
            })
            .await?
            .into_inner();
        resp.try_into()
    }

    pub(crate) async fn receive_payment(
        &self,
        amount_msat: Option<u64>,
        memo: &str,
    ) -> Result<ReceiveInvoice> {
        let mut client = self.inner.clone();
        let resp = client
            .receive_payment(pb::ReceivePaymentRequest {
                tenant_id: 0,
                amount_msat,
                memo: memo.to_owned(),
            })
            .await?
            .into_inner();
        resp.try_into()
    }

    pub(crate) async fn get_transactions(
        &self,
        limit: u32,
        before_timestamp: Option<i64>,
    ) -> Result<Vec<PaymentRecord>> {
        let mut client = self.inner.clone();
        let resp = client
            .get_transactions(pb::GetTransactionsRequest {
                tenant_id: 0,
                limit,
                before_timestamp,
            })
            .await?
            .into_inner();
        resp.payments
            .into_iter()
            .map(PaymentRecord::try_from)
            .collect()
    }

    pub(crate) async fn get_node_info(&self) -> Result<NodeInfo> {
        let mut client = self.inner.clone();
        let resp = client
            .get_node_info(pb::GetNodeInfoRequest { tenant_id: 0 })
            .await?
            .into_inner();
        resp.try_into()
    }

    pub(crate) async fn connect_peer(
        &self,
        peer: bitcoin::secp256k1::PublicKey,
        host: &str,
        port: u16,
    ) -> Result<()> {
        let mut client = self.inner.clone();
        client
            .connect_peer(pb::ConnectPeerRequest {
                tenant_id: 0,
                peer_pubkey_hex: hex::encode(peer.serialize()),
                host: host.to_owned(),
                port: u32::from(port),
            })
            .await?;
        Ok(())
    }

    pub(crate) async fn open_channel_init(
        &self,
        peer: bitcoin::secp256k1::PublicKey,
        channel_value_sat: u64,
        push_msat: u64,
    ) -> Result<([u8; 32], bitcoin::ScriptBuf, u64)> {
        let mut client = self.inner.clone();
        let resp = client
            .open_channel_init(pb::OpenChannelInitRequest {
                tenant_id: 0,
                peer_pubkey_hex: hex::encode(peer.serialize()),
                channel_value_sat,
                push_msat,
            })
            .await?
            .into_inner();

        if resp.temp_channel_id.len() != 32 {
            return Err(Error::InvalidResponse(format!(
                "temp_channel_id must be 32 bytes, got {}",
                resp.temp_channel_id.len()
            )));
        }
        let mut tcid = [0u8; 32];
        tcid.copy_from_slice(&resp.temp_channel_id);

        let script_bytes = hex::decode(&resp.funding_output_script_hex).map_err(|e| {
            Error::InvalidResponse(format!("funding_output_script_hex not hex: {e}"))
        })?;
        let script = bitcoin::ScriptBuf::from_bytes(script_bytes);

        Ok((tcid, script, resp.channel_value_sat))
    }

    pub(crate) async fn open_channel_finalize(
        &self,
        temp_channel_id: [u8; 32],
        peer: bitcoin::secp256k1::PublicKey,
        funding_tx: &bitcoin::Transaction,
    ) -> Result<()> {
        let tx_hex = hex::encode(bitcoin::consensus::serialize(funding_tx));
        let mut client = self.inner.clone();
        client
            .open_channel_finalize(pb::OpenChannelFinalizeRequest {
                tenant_id: 0,
                temp_channel_id: temp_channel_id.to_vec(),
                peer_pubkey_hex: hex::encode(peer.serialize()),
                funding_tx_hex: tx_hex,
            })
            .await?;
        Ok(())
    }

    pub(crate) async fn list_channels(&self) -> Result<Vec<ChannelSummary>> {
        let mut client = self.inner.clone();
        let resp = client
            .list_channels(pb::ListChannelsRequest { tenant_id: 0 })
            .await?
            .into_inner();
        resp.channels
            .into_iter()
            .map(ChannelSummary::try_from)
            .collect()
    }

    pub(crate) async fn get_lsp_info(&self) -> Result<LspInfo> {
        let mut client = self.inner.clone();
        let resp = client
            .get_lsp_info(pb::GetLspInfoRequest {})
            .await?
            .into_inner();
        resp.try_into()
    }

    pub(crate) async fn lsps2_get_info(&self, amount_msat: Option<u64>) -> Result<JitQuote> {
        let mut client = self.inner.clone();
        let resp = client
            .lsps2_get_info(pb::Lsps2GetInfoRequest { amount_msat })
            .await?
            .into_inner();
        resp.try_into()
    }

    pub(crate) async fn get_jit_invoice(&self, amount_msat: u64, memo: &str) -> Result<JitInvoice> {
        if amount_msat == 0 {
            return Err(Error::InvalidInput(
                "amount_msat must be > 0 for JIT invoices".to_owned(),
            ));
        }
        let mut client = self.inner.clone();
        let resp = client
            .get_jit_invoice(pb::GetJitInvoiceRequest {
                amount_msat,
                memo: memo.to_owned(),
            })
            .await?
            .into_inner();
        resp.try_into()
    }
}
