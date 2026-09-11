//! Translates watch specs into concrete ledger keys, and implements the poll
//! loop that observes, plans, and submits extends.

use rentkeeper_core::ledger_keys::LedgerKeys;
use stellar_xdr::{ContractDataDurability, LedgerKey, ReadXdr, ScVal};

use crate::config::{ValidConfig, WatchSpec};

/// Errors surfaced by the keeper loop.
#[derive(Debug, thiserror::Error)]
pub enum KeeperError {
    /// A watch spec could not be converted into ledger keys.
    #[error("invalid watch spec: {0}")]
    InvalidWatch(String),
    /// The RPC endpoint failed during observation or submission.
    #[error("rpc failure: {0}")]
    Rpc(String),
    /// Transaction building or signing failed.
    #[error("transaction failure: {0}")]
    Transaction(String),
}

/// Resolves watch specs into the concrete set of ledger keys to watch.
///
/// # Errors
/// Errors when a spec references malformed ids, hashes, or key XDR.
pub fn resolve_watch_keys(config: &ValidConfig) -> Result<Vec<LedgerKey>, KeeperError> {
    let mut keys = Vec::new();
    for spec in &config.watch {
        match spec {
            WatchSpec::Instance { contract_id } => {
                let id = contract_id_bytes(contract_id)?;
                keys.push(LedgerKeys::contract_data(
                    &id,
                    &instance_key(),
                    ContractDataDurability::Persistent,
                ));
            }
            WatchSpec::DataKey {
                contract_id,
                key_xdr,
                durability,
            } => {
                let id = contract_id_bytes(contract_id)?;
                let key = ScVal::from_xdr_base64(key_xdr.as_bytes(), stellar_xdr::Limits::none())
                    .map_err(|e| KeeperError::InvalidWatch(format!("key_xdr: {e}")))?;
                let durability = match durability.as_str() {
                    "persistent" => ContractDataDurability::Persistent,
                    "temporary" => ContractDataDurability::Temporary,
                    other => {
                        return Err(KeeperError::InvalidWatch(format!(
                            "unknown durability '{other}'"
                        )))
                    }
                };
                keys.push(LedgerKeys::contract_data(&id, &key, durability));
            }
            WatchSpec::ContractCode { wasm_hash } => {
                let hash = wasm_hash_bytes(wasm_hash)?;
                keys.push(LedgerKeys::contract_code(&hash));
            }
        }
    }
    Ok(keys)
}

fn contract_id_bytes(contract_id: &str) -> Result<[u8; 32], KeeperError> {
    let strkey = stellar_strkey::Strkey::from_string(contract_id)
        .map_err(|e| KeeperError::InvalidWatch(format!("contract_id: {e}")))?;
    match strkey {
        stellar_strkey::Strkey::Contract(stellar_strkey::Contract(bytes)) => Ok(bytes),
        _ => Err(KeeperError::InvalidWatch(format!(
            "{contract_id} is not a C... contract strkey"
        ))),
    }
}

fn wasm_hash_bytes(wasm_hash: &str) -> Result<[u8; 32], KeeperError> {
    let stripped = wasm_hash.strip_prefix("0x").unwrap_or(wasm_hash);
    let mut out = [0u8; 32];
    for (i, chunk) in stripped.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0]).ok_or_else(|| KeeperError::InvalidWatch("wasm_hash".into()))?;
        let lo = chunk
            .get(1)
            .and_then(|c| hex_val(*c))
            .ok_or_else(|| KeeperError::InvalidWatch("wasm_hash".into()))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The reserved `ScVal` key Soroban uses for the contract instance entry.
#[must_use]
pub fn instance_key() -> ScVal {
    ScVal::LedgerKeyContractInstance
}
