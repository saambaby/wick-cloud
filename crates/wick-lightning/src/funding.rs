//! [`FundingSource`] — callback that materialises a signed on-chain funding
//! transaction for LDK's `Event::FundingGenerationReady`.
//!
//! Wick is self-custodial: the server's Lightning node holds no on-chain
//! coins. The on-chain wallet lives on the user's device (Flutter / WASM SDK).
//! This trait is the seam between the two: LDK asks for "pay `output_script`
//! exactly `channel_value_sats`", the [`FundingSource`] impl returns the signed
//! tx, and [`crate::EventHandler`] forwards it to
//! `ChannelManager::funding_transaction_generated`.
//!
//! The output script must be satisfied exactly; `channel_value_sats` is the
//! channel capacity LDK is about to commit to. Funds sent to a different
//! script or in a different amount are rejected by LDK and the channel is
//! abandoned.

use std::fmt::Debug;

use bitcoin::{ ScriptBuf, Transaction };

/// Callback that produces a signed on-chain funding tx.
///
/// Called synchronously from inside the LDK event processing task; impls
/// that need to await should use an internal runtime handle or
/// `block_in_place`.
pub trait FundingSource: Send + Sync + Debug + 'static {
    /// Produce a fully-signed transaction that pays `output_script` exactly
    /// `channel_value_sats` in a single output. LDK will broadcast it via
    /// the configured `BroadcasterInterface`.
    ///
    /// Returning `Err` abandons the channel open (LDK fires
    /// `Event::ChannelClosed`). Implementations should return a descriptive
    /// error on insufficient balance / signing failure so the test
    /// diagnostic loop can surface it.
    fn fund_channel(
        &self,
        output_script: ScriptBuf,
        channel_value_sats: u64
    ) -> anyhow::Result<Transaction>;
}
