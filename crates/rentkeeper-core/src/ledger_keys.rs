//! Ledger key construction, rendering, and hashing for Soroban state entries.
//!
//! Everything the rent keeper touches lives in the contract-data, contract-code,
//! config-setting, and TTL parts of the ledger key space. Keys are also kept as
//! XDR bytes because the TTL entry for an entry is addressed by the SHA-256 hash
//! of the entry's ledger key XDR.

use sha2::{Digest, Sha256};
use stellar_xdr::{
    ConfigSettingId, ContractDataDurability, Hash, LedgerKey, LedgerKeyConfigSetting,
    LedgerKeyContractCode, LedgerKeyContractData, LedgerKeyTtl, Limits, ScVal, WriteXdr,
};

/// Builds, renders, and hashes Soroban ledger keys relevant to rent keeping.
#[derive(Debug, Clone, Copy, Default)]
pub struct LedgerKeys;

impl LedgerKeys {
    /// Ledger key for a contract data entry.
    #[must_use]
    pub fn contract_data(
        contract_id: &[u8; 32],
        key: &ScVal,
        durability: ContractDataDurability,
    ) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(Hash(*contract_id))),
            key: key.clone(),
            durability,
        })
    }

    /// Ledger key for deployed contract Wasm.
    #[must_use]
    pub fn contract_code(wasm_hash: &[u8; 32]) -> LedgerKey {
        LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: Hash(*wasm_hash),
        })
    }

    /// Ledger key for a network config setting (e.g. state archival limits).
    #[must_use]
    pub fn config_setting(id: ConfigSettingId) -> LedgerKey {
        LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: id,
        })
    }

    /// Ledger key for the TTL companion entry of `entry_key`.
    ///
    /// The TTL entry is keyed by the SHA-256 of the entry's own XDR encoding.
    pub fn ttl_for(entry_key: &LedgerKey) -> Result<LedgerKey, crate::error::RentkeeperError> {
        let xdr = entry_key
            .to_xdr(Limits::none())
            .map_err(|e| crate::error::RentkeeperError::Xdr(e.to_string()))?;
        let hash: [u8; 32] = Sha256::digest(xdr).into();
        Ok(LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: Hash(hash),
        }))
    }

    /// Canonical base64 XDR rendering of a ledger key, used in logs and plans.
    ///
    /// # Errors
    /// Returns an error if the key cannot be XDR-encoded.
    pub fn render(key: &LedgerKey) -> Result<String, crate::error::RentkeeperError> {
        key.to_xdr_base64(Limits::none())
            .map_err(|e| crate::error::RentkeeperError::Xdr(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::ReadXdr;

    fn example_contract_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0xAB;
        id
    }

    fn example_scval() -> ScVal {
        ScVal::U32(7)
    }

    #[test]
    fn contract_data_key_roundtrips_through_xdr() {
        let key = LedgerKeys::contract_data(
            &example_contract_id(),
            &example_scval(),
            ContractDataDurability::Persistent,
        );
        let rendered = LedgerKeys::render(&key).expect("renders");
        let parsed =
            LedgerKey::from_xdr_base64(rendered.as_bytes(), Limits::none()).expect("parses back");
        assert_eq!(parsed, key);
    }

    #[test]
    fn ttl_key_is_sha256_of_entry_key_xdr() {
        let key = LedgerKeys::contract_data(
            &example_contract_id(),
            &example_scval(),
            ContractDataDurability::Temporary,
        );
        let ttl = LedgerKeys::ttl_for(&key).expect("ttl key");
        let expected_hash: [u8; 32] =
            Sha256::digest(key.to_xdr(Limits::none()).expect("xdr")).into();

        match ttl {
            LedgerKey::Ttl(entry) => assert_eq!(entry.key_hash.0, expected_hash),
            other => panic!("expected TTL key, got {other:?}"),
        }
    }

    #[test]
    fn ttl_key_is_deterministic() {
        let key = LedgerKeys::contract_code(&example_contract_id());
        let a = LedgerKeys::ttl_for(&key).expect("ttl a");
        let b = LedgerKeys::ttl_for(&key).expect("ttl b");
        assert_eq!(a, b);
    }

    #[test]
    fn contract_code_key_carries_hash() {
        let key = LedgerKeys::contract_code(&example_contract_id());
        match key {
            LedgerKey::ContractCode(entry) => assert_eq!(entry.hash.0, example_contract_id()),
            other => panic!("expected contract code key, got {other:?}"),
        }
    }

    #[test]
    fn config_setting_key_carries_id() {
        let key = LedgerKeys::config_setting(ConfigSettingId::StateArchival);
        match key {
            LedgerKey::ConfigSetting(entry) => {
                assert_eq!(entry.config_setting_id, ConfigSettingId::StateArchival)
            }
            other => panic!("expected config setting key, got {other:?}"),
        }
    }
}
