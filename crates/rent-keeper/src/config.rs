//! Daemon configuration: TOML file plus optional environment overrides.

use serde::Deserialize;

/// Top-level daemon configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Stellar RPC endpoint, e.g. `https://soroban-testnet.stellar.org:443`.
    pub rpc_url: String,
    /// Network passphrase, e.g. `Test SDF Network ; September 2015`.
    pub network_passphrase: String,
    /// Secret `S...` seed of the fee payer account.
    pub secret_key: String,
    /// Watch specification (entries the daemon must keep alive).
    #[serde(default)]
    pub watch: Vec<WatchSpec>,
    /// Poll interval in seconds (default 30).
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// Risk window in days; entries with TTL below it get extended (default 7).
    #[serde(default = "default_risk_window_days")]
    pub risk_window_days: f64,
    /// Port for the Prometheus metrics endpoint; disabled when None.
    #[serde(default)]
    pub metrics_port: Option<u16>,
}

/// One watch rule telling the daemon which ledger entries to protect.
///
/// RPC addresses entries by key, so watches are always explicit; there is no
/// wildcard that covers "every entry of a contract".
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WatchSpec {
    /// The contract instance entry (the `LedgerKeyContractInstance` key).
    Instance {
        /// `C...` contract strkey.
        contract_id: String,
    },
    /// One explicit contract data entry.
    DataKey {
        /// `C...` contract strkey.
        contract_id: String,
        /// Base64 XDR of the `ScVal` key.
        key_xdr: String,
        /// `persistent` or `temporary`.
        durability: String,
    },
    /// The deployed Wasm code entry for a hash.
    ContractCode {
        /// Hex-encoded 32-byte Wasm hash (with or without 0x).
        wasm_hash: String,
    },
}

fn default_poll_interval_secs() -> u64 {
    30
}

fn default_risk_window_days() -> f64 {
    7.0
}
