//! Errors shared across the Soroban Rent Keeper crates.

use thiserror::Error;

/// Top-level error type for the Rent Keeper framework.
#[derive(Debug, Error)]
pub enum RentkeeperError {
    /// A ledger entry referenced by a plan was not found in ledger state.
    #[error("ledger entry not found: {0}")]
    EntryNotFound(String),

    /// The caller asked for a durability the entry does not have.
    #[error("entry {entry} is {actual} but plan was built for {expected} durability")]
    DurabilityMismatch {
        /// XDR-rendered ledger key of the offending entry.
        entry: String,
        /// Durability the plan expected.
        expected: String,
        /// Durability actually observed.
        actual: String,
    },

    /// An error surfaced by the Stellar RPC endpoint.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// XDR encode/decode failure.
    #[error("xdr error: {0}")]
    Xdr(String),

    /// Key material could not be parsed, validated, or used.
    #[error("key error: {0}")]
    Key(String),

    /// Transaction building or signing failed.
    #[error("transaction error: {0}")]
    Transaction(String),

    /// Configuration was incomplete or inconsistent.
    #[error("config error: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_not_found_renders_key() {
        let err = RentkeeperError::EntryNotFound("ContractData/abc".to_string());
        assert_eq!(err.to_string(), "ledger entry not found: ContractData/abc");
    }

    #[test]
    fn durability_mismatch_names_both_sides() {
        let err = RentkeeperError::DurabilityMismatch {
            entry: "ContractData/k".to_string(),
            expected: "Persistent".to_string(),
            actual: "Temporary".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Persistent"));
        assert!(msg.contains("Temporary"));
    }
}
