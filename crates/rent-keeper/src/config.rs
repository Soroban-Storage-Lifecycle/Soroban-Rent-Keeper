//! Daemon configuration: TOML file plus optional environment overrides.

use std::path::PathBuf;

use rentkeeper_core::ttl::{RiskWindow, TtlConstants};
use serde::Deserialize;
use stellar_xdr::ReadXdr;

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

/// A fully validated configuration ready to run with.
#[derive(Debug, Clone)]
pub struct ValidConfig {
    /// RPC endpoint URL.
    pub rpc_url: String,
    /// Network passphrase for signing.
    pub network_passphrase: String,
    /// Fee payer secret (never logged).
    pub secret_key: String,
    /// Validated watch rules.
    pub watch: Vec<WatchSpec>,
    /// Poll cadence.
    pub poll_interval: std::time::Duration,
    /// Risk window in ledgers.
    pub risk_window: RiskWindow,
    /// Metrics endpoint port.
    pub metrics_port: Option<u16>,
    /// TTL constants (network-sourced when available, else public defaults).
    pub constants: TtlConstants,
}

/// Loads and validates a daemon configuration from a TOML file.
///
/// # Errors
/// Errors on unreadable files, invalid TOML, or semantically invalid values
/// (unknown durability names, malformed hashes or key XDR, non-positive
/// windows).
pub fn load_config(path: &PathBuf) -> Result<ValidConfig, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    let config: Config =
        toml::from_str(&raw).map_err(|e| format!("invalid TOML in {}: {e}", path.display()))?;

    if config.rpc_url.is_empty() {
        return Err("rpc_url must not be empty".to_string());
    }
    if config.network_passphrase.is_empty() {
        return Err("network_passphrase must not be empty".to_string());
    }
    if !config.secret_key.starts_with('S') {
        return Err("secret_key must be an S... secret strkey".to_string());
    }
    if config.poll_interval_secs == 0 {
        return Err("poll_interval_secs must be positive".to_string());
    }
    if !(config.risk_window_days.is_finite() && config.risk_window_days > 0.0) {
        return Err("risk_window_days must be a positive number".to_string());
    }
    if config.watch.is_empty() {
        return Err("at least one [[watch]] rule is required".to_string());
    }
    for (i, spec) in config.watch.iter().enumerate() {
        validate_watch_spec(spec).map_err(|e| format!("watch[{i}]: {e}"))?;
    }

    Ok(ValidConfig {
        rpc_url: config.rpc_url,
        network_passphrase: config.network_passphrase,
        secret_key: config.secret_key,
        risk_window: RiskWindow::from_days(config.risk_window_days),
        poll_interval: std::time::Duration::from_secs(config.poll_interval_secs),
        watch: config.watch,
        metrics_port: config.metrics_port,
        constants: TtlConstants::stellar_public(),
    })
}

fn validate_watch_spec(spec: &WatchSpec) -> Result<(), String> {
    match spec {
        WatchSpec::Instance { contract_id } => validate_contract_strkey(contract_id),
        WatchSpec::DataKey {
            contract_id,
            key_xdr,
            durability,
        } => {
            validate_contract_strkey(contract_id)?;
            validate_durability_name(durability)?;
            stellar_xdr::ScVal::from_xdr_base64(key_xdr.as_bytes(), stellar_xdr::Limits::none())
                .map_err(|e| format!("key_xdr: {e}"))?;
            Ok(())
        }
        WatchSpec::ContractCode { wasm_hash } => validate_hex_hash(wasm_hash),
    }
}

fn validate_contract_strkey(id: &str) -> Result<(), String> {
    let strkey =
        stellar_strkey::Strkey::from_string(id).map_err(|e| format!("contract_id: {e}"))?;
    match strkey {
        stellar_strkey::Strkey::Contract(_) => Ok(()),
        _ => Err(format!("contract_id {id} is not a C... contract strkey")),
    }
}

fn validate_durability_name(name: &str) -> Result<(), String> {
    match name {
        "persistent" | "temporary" => Ok(()),
        other => Err(format!(
            "unknown durability '{other}' (expected 'persistent' or 'temporary')"
        )),
    }
}

fn validate_hex_hash(hash: &str) -> Result<(), String> {
    let stripped = hash.strip_prefix("0x").unwrap_or(hash);
    if stripped.len() != 64 || !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("wasm_hash '{hash}' is not 32 hex-encoded bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid testnet-format contract strkey (any C... strkey parses).
    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn base_config() -> String {
        format!(
            r#"
rpc_url = "https://soroban-testnet.stellar.org:443"
network_passphrase = "Test SDF Network ; September 2015"
secret_key = "SBFIJNQVTU3QZGZSVAHBQFAKHRGFNIHQMIVJJSGV7HRPC7CLBR7QZL7VYP"
[[watch]]
type = "instance"
contract_id = "{CONTRACT}"
"#
        )
    }

    fn write_tmp(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rentkeeper-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("config.toml");
        std::fs::write(&path, contents).expect("write");
        path
    }

    fn cleanup(path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn minimal_config_loads_with_defaults() {
        let path = write_tmp("ok", &base_config());
        let config = load_config(&path).expect("loads");
        assert_eq!(config.poll_interval, std::time::Duration::from_secs(30));
        assert_eq!(config.risk_window.alert_horizon_ledgers, 120_960);
        assert!(config.metrics_port.is_none());
        assert_eq!(config.watch.len(), 1);
        cleanup(&path);
    }

    #[test]
    fn empty_rpc_url_is_rejected() {
        let contents = base_config().replace("https://soroban-testnet.stellar.org:443", "");
        let path = write_tmp("emptyrpc", &contents);
        let err = load_config(&path).expect_err("must fail");
        assert!(err.contains("rpc_url"));
        cleanup(&path);
    }

    #[test]
    fn non_secret_key_is_rejected() {
        let contents = base_config().replace("secret_key = \"S", "secret_key = \"G");
        let path = write_tmp("badkey", &contents);
        let err = load_config(&path).expect_err("must fail");
        assert!(err.contains("secret_key"));
        cleanup(&path);
    }

    #[test]
    fn account_strkey_is_not_a_contract() {
        let contents = base_config().replace(
            CONTRACT,
            "GA7QYNF7SowQc3RwGxDq2jTnKlViNgmLnCATJznaXStreaming",
        );
        let path = write_tmp("badcid", &contents);
        assert!(load_config(&path).is_err());
        cleanup(&path);
    }

    #[test]
    fn data_key_watch_validates_xdr() {
        // ScVal::U32(7) as base64 XDR: tag SCV_U32 (=3) + big-endian uint32.
        let contents = base_config()
            + r#"
[[watch]]
type = "data_key"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
key_xdr = "AAAAAwAAAAc="
durability = "persistent"
"#;
        let path = write_tmp("datakey", &contents);
        let config = load_config(&path).expect("loads");
        assert_eq!(config.watch.len(), 2);
        cleanup(&path);
    }

    #[test]
    fn invalid_data_key_xdr_is_rejected() {
        let contents = base_config()
            + r#"
[[watch]]
type = "data_key"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
key_xdr = "!!!not-base64-xdr!!!"
durability = "persistent"
"#;
        let path = write_tmp("badkeyxdr", &contents);
        let err = load_config(&path).expect_err("must fail");
        assert!(err.contains("key_xdr"));
        cleanup(&path);
    }

    #[test]
    fn unknown_durability_is_rejected() {
        let contents = base_config()
            + r#"
[[watch]]
type = "data_key"
contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
key_xdr = "AAAAAwAAAAc="
durability = "eternal"
"#;
        let path = write_tmp("baddur", &contents);
        let err = load_config(&path).expect_err("must fail");
        assert!(err.contains("unknown durability"));
        cleanup(&path);
    }

    #[test]
    fn malformed_wasm_hash_is_rejected() {
        let contents = base_config()
            + r#"
[[watch]]
type = "contract_code"
wasm_hash = "zzzz"
"#;
        let path = write_tmp("badhash", &contents);
        let err = load_config(&path).expect_err("must fail");
        assert!(err.contains("wasm_hash"));
        cleanup(&path);
    }

    #[test]
    fn zero_poll_interval_is_rejected() {
        // poll_interval_secs must come before any [[watch]] table so it stays
        // a top-level key in TOML.
        let contents = format!(
            r#"
rpc_url = "https://soroban-testnet.stellar.org:443"
network_passphrase = "Test SDF Network ; September 2015"
secret_key = "SBFIJNQVTU3QZGZSVAHBQFAKHRGFNIHQMIVJJSGV7HRPC7CLBR7QZL7VYP"
poll_interval_secs = 0
[[watch]]
type = "instance"
contract_id = "{CONTRACT}"
"#
        );
        let path = write_tmp("zeropoll", &contents);
        let err = load_config(&path).expect_err("must fail");
        assert!(err.contains("poll_interval_secs"));
        cleanup(&path);
    }

    #[test]
    fn empty_watch_list_is_rejected() {
        let contents = r#"
rpc_url = "https://soroban-testnet.stellar.org:443"
network_passphrase = "Test SDF Network ; September 2015"
secret_key = "SBFIJNQVTU3QZGZSVAHBQFAKHRGFNIHQMIVJJSGV7HRPC7CLBR7QZL7VYP"
"#;
        let path = write_tmp("nowatch", contents);
        let err = load_config(&path).expect_err("must fail");
        assert!(err.contains("[[watch]]"));
        cleanup(&path);
    }

    #[test]
    fn missing_file_is_a_clean_error() {
        let err = load_config(&PathBuf::from("/nonexistent/config.toml")).expect_err("must fail");
        assert!(err.contains("cannot read config"));
    }
}
