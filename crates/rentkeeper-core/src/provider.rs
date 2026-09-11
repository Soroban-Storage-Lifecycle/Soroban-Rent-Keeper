//! RPC provider: reads ledger entries and TTL state from a Soroban RPC node.
//!
//! The provider owns all network interaction for the framework. Planners stay
//! pure so they can be unit-tested offline.

use sha2::Digest;
use stellar_rpc_client::Client as SorobanRpcClient;
use stellar_xdr::{
    ConfigSettingId, LedgerEntryData, LedgerKey, Limits, ReadXdr, StateArchivalSettings, WriteXdr,
};

use crate::error::RentkeeperError;
use crate::ledger_keys::LedgerKeys;
use crate::ttl::{ArchivedEntryInfo, EntryTtl, TtlConstants};

/// Thin wrapper around the Soroban RPC client used for observations.
#[derive(Debug, Clone)]
pub struct SorobanProvider {
    rpc_url: String,
    client: SorobanRpcClient,
}

impl SorobanProvider {
    /// Connects to the RPC endpoint at `rpc_url`.
    ///
    /// # Errors
    /// Returns an error when the URL is invalid or the client cannot be built.
    pub fn connect(rpc_url: &str) -> Result<Self, RentkeeperError> {
        let client = SorobanRpcClient::new(rpc_url)
            .map_err(|e| RentkeeperError::Rpc(format!("client for {rpc_url}: {e}")))?;
        Ok(Self {
            rpc_url: rpc_url.to_string(),
            client,
        })
    }

    /// The RPC URL this provider talks to.
    #[must_use]
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Submits a signed transaction envelope and returns its hash.
    ///
    /// # Errors
    /// Errors on transport failures and node-side rejections.
    pub async fn send_transaction(
        &self,
        envelope: &stellar_xdr::TransactionEnvelope,
    ) -> Result<stellar_xdr::Hash, RentkeeperError> {
        self.client
            .send_transaction(envelope)
            .await
            .map_err(|e| RentkeeperError::Rpc(format!("send_transaction: {e}")))
    }

    /// Fetches an account entry by `G...` strkey (used for sequence numbers).
    ///
    /// # Errors
    /// Errors when the account is missing or the RPC call fails.
    pub async fn get_account(
        &self,
        account_id_strkey: &str,
    ) -> Result<stellar_xdr::AccountEntry, RentkeeperError> {
        self.client
            .get_account(account_id_strkey)
            .await
            .map_err(|e| RentkeeperError::Rpc(format!("get_account: {e}")))
    }

    /// Fetches the network's state archival settings for TTL math.
    ///
    /// # Errors
    /// Errors when the RPC call fails or the config entry cannot be decoded.
    pub async fn ttl_constants(&self) -> Result<TtlConstants, RentkeeperError> {
        let key = LedgerKeys::config_setting(ConfigSettingId::StateArchival);
        let response = self
            .client
            .get_ledger_entries(&[key])
            .await
            .map_err(|e| RentkeeperError::Rpc(format!("config settings: {e}")))?;

        let entry = response
            .entries
            .unwrap_or_default()
            .into_iter()
            .next()
            .ok_or_else(|| {
                RentkeeperError::Config("StateArchival config entry missing from node".to_string())
            })?;

        let ledger_entry =
            stellar_xdr::LedgerEntry::from_xdr_base64(entry.xdr.as_bytes(), Limits::none())
                .map_err(|e| RentkeeperError::Xdr(format!("config entry: {e}")))?;

        match ledger_entry.data {
            LedgerEntryData::ConfigSetting(stellar_xdr::ConfigSettingEntry::StateArchival(
                settings,
            )) => Ok(state_archival_to_constants(&settings)),
            _ => Err(RentkeeperError::Config(
                "StateArchival key returned a different entry type".to_string(),
            )),
        }
    }

    /// Observes the TTL state of the given keys at the node's current ledger.
    ///
    /// For each non-TTL key the companion TTL entry is fetched too; its
    /// `live_until_ledger_seq` is the source of truth for liveness. Returns one
    /// row per requested key, preserving input order. Rows for keys that are
    /// entirely absent from ledger state carry `archived = true`.
    ///
    /// # Errors
    /// Errors when the RPC call fails or an entry cannot be decoded.
    pub async fn observe_entries(
        &self,
        keys: &[LedgerKey],
    ) -> Result<Vec<Observation>, RentkeeperError> {
        let mut all_keys = keys.to_vec();
        let ttl_keys: Vec<LedgerKey> = keys
            .iter()
            .filter(|k| !matches!(k, LedgerKey::Ttl(_)))
            .filter_map(|k| LedgerKeys::ttl_for(k).ok())
            .collect();
        all_keys.extend(ttl_keys);

        let response = self
            .client
            .get_ledger_entries(&all_keys)
            .await
            .map_err(|e| RentkeeperError::Rpc(format!("getLedgerEntries: {e}")))?;
        let latest = u32::try_from(response.latest_ledger).unwrap_or_default();

        // Index what came back by the entry's own key.
        let mut live_until: std::collections::HashMap<[u8; 32], u32> =
            std::collections::HashMap::new();
        let mut present: std::collections::HashMap<[u8; 32], u32> =
            std::collections::HashMap::new();
        for result in response.entries.unwrap_or_default() {
            let entry =
                stellar_xdr::LedgerEntry::from_xdr_base64(result.xdr.as_bytes(), Limits::none())
                    .map_err(|e| RentkeeperError::Xdr(format!("entry decode: {e}")))?;
            let key_xdr = entry
                .to_key()
                .to_xdr(Limits::none())
                .map_err(|e| RentkeeperError::Xdr(e.to_string()))?;
            let mut key_hash: [u8; 32] = sha2::Sha256::digest(&key_xdr).into();
            // For TTL entries the key_hash *is* the hash of the watched key.
            if let LedgerEntryData::Ttl(ttl) = &entry.data {
                key_hash = ttl.key_hash.0;
                live_until.insert(key_hash, ttl.live_until_ledger_seq);
            } else {
                present.insert(key_hash, entry.last_modified_ledger_seq);
            }
        }

        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let key_xdr = key
                .to_xdr(Limits::none())
                .map_err(|e| RentkeeperError::Xdr(e.to_string()))?;
            let hashed: [u8; 32] = sha2::Sha256::digest(&key_xdr).into();
            if matches!(key, LedgerKey::Ttl(_)) {
                // Callers watch TTL keys directly (rare); report from the entry itself.
                let observation = live_until
                    .get(&hashed)
                    .map(|live_until| Observation {
                        current_ledger: latest,
                        entry: EntryState::Live(EntryTtl {
                            current_ledger: latest,
                            live_until_ledger_seq: Some(*live_until),
                        }),
                    })
                    .unwrap_or(Observation {
                        current_ledger: latest,
                        entry: EntryState::Archived(ArchivedEntryInfo {
                            current_ledger: latest,
                            archived: true,
                        }),
                    });
                out.push(observation);
                continue;
            }

            let entry_present = present.contains_key(&hashed);
            match live_until.get(&hashed) {
                Some(&live_until) if live_until > latest => out.push(Observation {
                    current_ledger: latest,
                    entry: EntryState::Live(EntryTtl {
                        current_ledger: latest,
                        live_until_ledger_seq: Some(live_until),
                    }),
                }),
                Some(_) => out.push(Observation {
                    current_ledger: latest,
                    entry: EntryState::ExpiredButPresent(ArchivedEntryInfo {
                        current_ledger: latest,
                        archived: false,
                    }),
                }),
                None if entry_present => out.push(Observation {
                    current_ledger: latest,
                    entry: EntryState::Live(EntryTtl {
                        current_ledger: latest,
                        live_until_ledger_seq: None,
                    }),
                }),
                None => out.push(Observation {
                    current_ledger: latest,
                    entry: EntryState::Archived(ArchivedEntryInfo {
                        current_ledger: latest,
                        archived: true,
                    }),
                }),
            }
        }
        Ok(out)
    }
}

/// What the provider learned about one watched entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryState {
    /// Entry is live with a TTL entry present.
    Live(EntryTtl),
    /// Entry data still exists but its TTL has passed; needs restore.
    ExpiredButPresent(ArchivedEntryInfo),
    /// Entry (and its TTL) is gone from state; archived, needs restore.
    Archived(ArchivedEntryInfo),
}

/// One observation result for a requested key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Ledger height of the snapshot.
    pub current_ledger: u32,
    /// The observed state.
    pub entry: EntryState,
}

impl Observation {
    /// Convenience accessor treating the observation as a plain TTL snapshot.
    ///
    /// Expired and archived observations report the snapshot ledger with no
    /// `live_until_ledger_seq`, which planners treat as "not extendable".
    #[must_use]
    pub fn as_entry_ttl(&self) -> EntryTtl {
        match &self.entry {
            EntryState::Live(ttl) => *ttl,
            EntryState::ExpiredButPresent(info) | EntryState::Archived(info) => EntryTtl {
                current_ledger: info.current_ledger,
                live_until_ledger_seq: None,
            },
        }
    }

    /// True when the entry needs a restore rather than an extend.
    #[must_use]
    pub fn needs_restore(&self) -> bool {
        matches!(
            self.entry,
            EntryState::ExpiredButPresent(_) | EntryState::Archived(_)
        )
    }
}

/// Converts XDR state archival settings into planner constants.
#[must_use]
pub fn state_archival_to_constants(settings: &StateArchivalSettings) -> TtlConstants {
    TtlConstants {
        seconds_per_ledger: 5,
        max_entry_ttl: settings.max_entry_ttl,
        min_persistent_ttl: settings.min_persistent_ttl,
        min_temporary_ttl: settings.min_temporary_ttl,
    }
}

/// Re-exports for downstream crates that need the durability type.
pub use stellar_xdr::ContractDataDurability as XdrDurability;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_archival_settings_map_to_constants() {
        let settings = StateArchivalSettings {
            max_entry_ttl: 6_312_000,
            min_temporary_ttl: 409_600,
            min_persistent_ttl: 409_600,
            persistent_rent_rate_denominator: 0,
            temp_rent_rate_denominator: 0,
            max_entries_to_archive: 0,
            live_soroban_state_size_window_sample_size: 0,
            live_soroban_state_size_window_sample_period: 0,
            eviction_scan_size: 0,
            starting_eviction_scan_level: 0,
        };
        let constants = state_archival_to_constants(&settings);
        assert_eq!(constants.max_entry_ttl, 6_312_000);
        assert_eq!(constants.min_persistent_ttl, 409_600);
        assert_eq!(constants.seconds_per_ledger, 5);
    }

    #[test]
    fn observation_classifies_restore_need() {
        let live = Observation {
            current_ledger: 10,
            entry: EntryState::Live(EntryTtl {
                current_ledger: 10,
                live_until_ledger_seq: Some(20),
            }),
        };
        let archived = Observation {
            current_ledger: 10,
            entry: EntryState::Archived(ArchivedEntryInfo {
                current_ledger: 10,
                archived: true,
            }),
        };
        let expired = Observation {
            current_ledger: 10,
            entry: EntryState::ExpiredButPresent(ArchivedEntryInfo {
                current_ledger: 10,
                archived: false,
            }),
        };
        assert!(!live.needs_restore());
        assert!(archived.needs_restore());
        assert!(expired.needs_restore());
        assert_eq!(live.as_entry_ttl().ttl_ledgers(), Some(10));
        assert_eq!(archived.as_entry_ttl().ttl_ledgers(), None);
    }

    // Silences unused-import warnings for types exercised only in integration.
    #[allow(unused_qualifications)]
    fn _type_witnesses() {
        let _d: Option<stellar_xdr::ContractDataDurability> = None;
        let _v: Option<stellar_xdr::ScVal> = None;
        let _e: Option<stellar_xdr::Error> = None;
    }
}
