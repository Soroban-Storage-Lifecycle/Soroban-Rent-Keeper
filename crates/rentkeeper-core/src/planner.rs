//! Planner that turns ledger-entry observations into extend/restore plans.
//!
//! The planner is pure: it takes snapshots of entry TTL state and produces an
//! [`ArchivalPlan`]. Network interaction lives in [`crate::provider`].

use stellar_xdr::LedgerKey;

use crate::error::RentkeeperError;
use crate::plan::{ArchivalPlan, OperationKind};
use crate::ttl::{ArchivedEntryInfo, Durability, EntryTtl, RiskWindow, TtlConstants};
use crate::{ledger_keys::LedgerKeys, plan::PlanEntry};

/// Builds extend and restore plans from entry observations.
#[derive(Debug, Clone)]
pub struct Planner {
    constants: TtlConstants,
    window: RiskWindow,
    network_passphrase: String,
}

impl Planner {
    /// Creates a planner for a network with the given constants and risk window.
    #[must_use]
    pub fn new(constants: TtlConstants, window: RiskWindow, network_passphrase: &str) -> Self {
        Self {
            constants,
            window,
            network_passphrase: network_passphrase.to_string(),
        }
    }

    /// The configured network passphrase.
    #[must_use]
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// The configured risk window.
    #[must_use]
    pub const fn risk_window(&self) -> &RiskWindow {
        &self.window
    }

    /// Builds an extend plan for live entries at or below the alert horizon.
    ///
    /// `observations` maps each candidate ledger key to its observed TTL state.
    /// Entries whose TTL is `None` (no TTL entry) or above the horizon are
    /// excluded. The plan's `extend_to` is clamped to the network
    /// `max_entry_ttl`.
    ///
    /// # Errors
    /// Returns an error if any key cannot be rendered to XDR.
    pub fn plan_extend(
        &self,
        observations: &[(LedgerKey, EntryTtl)],
        current_ledger: u32,
    ) -> Result<ArchivalPlan, RentkeeperError> {
        let mut entries = Vec::new();
        for (key, ttl) in observations {
            if !self.window.is_at_risk(ttl) {
                continue;
            }
            let durability = durability_of(key);
            let ttl = renormalize_ttl(ttl, current_ledger);
            entries.push(PlanEntry {
                key_xdr: LedgerKeys::render(key)?,
                key: key.clone(),
                kind: OperationKind::Extend,
                durability,
                ttl,
            });
        }
        Ok(ArchivalPlan {
            network_passphrase: self.network_passphrase.clone(),
            reference_ledger: current_ledger,
            extend_to: self.window.extend_to_ledgers(&self.constants),
            entries,
        })
    }

    /// Builds a restore plan for archived entries.
    ///
    /// Restore covers entries that no longer appear in ledger state (their TTL
    /// entry is gone) plus live-but-expired edge cases (`live_until_ledger_seq`
    /// at or before the current ledger). Restored entries are immediately
    /// extended to the plan's `extend_to` because a restore transaction may
    /// carry a single `RestoreFootprint` op whose footprint already contains
    /// the entries; the follow-up extend is a separate plan.
    ///
    /// # Errors
    /// Returns an error if any key cannot be rendered to XDR.
    pub fn plan_restore(
        &self,
        observations: &[(LedgerKey, ArchivedEntryInfo)],
        current_ledger: u32,
    ) -> Result<ArchivalPlan, RentkeeperError> {
        let mut entries = Vec::new();
        for (key, info) in observations {
            if !info.is_archived() {
                continue;
            }
            let ttl = EntryTtl {
                current_ledger,
                live_until_ledger_seq: None,
            };
            let durability = durability_of(key);
            entries.push(PlanEntry {
                key_xdr: LedgerKeys::render(key)?,
                key: key.clone(),
                kind: OperationKind::Restore,
                durability,
                ttl,
            });
        }
        Ok(ArchivalPlan {
            network_passphrase: self.network_passphrase.clone(),
            reference_ledger: current_ledger,
            extend_to: self.window.extend_to_ledgers(&self.constants),
            entries,
        })
    }

    /// Classifies a TTL companion entry: when its `live_until_ledger_seq` is
    /// at or before the current ledger, the watched entry has expired.
    ///
    /// Watchers use this when deciding between the extend and restore paths.
    #[must_use]
    pub fn classify_ttl_entry(
        ttl_entry: &stellar_xdr::TtlEntry,
        current_ledger: u32,
    ) -> TtlVerdict {
        if ttl_entry.live_until_ledger_seq <= current_ledger {
            TtlVerdict::Expired
        } else {
            TtlVerdict::Live {
                remaining: u64::from(ttl_entry.live_until_ledger_seq) - u64::from(current_ledger),
            }
        }
    }
}

/// Verdict for a TTL companion entry observed on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlVerdict {
    /// The TTL entry exists and the watched entry is still live.
    Live {
        /// Ledgers remaining until expiry.
        remaining: u64,
    },
    /// The TTL entry exists but the watched entry has already expired.
    Expired,
}

fn durability_of(key: &LedgerKey) -> Option<Durability> {
    match key {
        LedgerKey::ContractData(data) => Some(Durability::from_xdr(data.durability)),
        _ => None,
    }
}

/// Rewrites an observation taken at `ttl.current_ledger` so its TTL is
/// expressed against `current_ledger` instead, without on-chain re-fetch.
fn renormalize_ttl(ttl: &EntryTtl, current_ledger: u32) -> EntryTtl {
    EntryTtl {
        current_ledger,
        live_until_ledger_seq: ttl.live_until_ledger_seq,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_keys::LedgerKeys;
    use stellar_xdr::{ContractDataDurability, ScVal};

    fn constants() -> TtlConstants {
        TtlConstants::stellar_public()
    }

    fn planner() -> Planner {
        Planner::new(
            constants(),
            RiskWindow {
                alert_horizon_ledgers: 1_000,
            },
            "Test SDF Network ; September 2015",
        )
    }

    fn data_key(durability: ContractDataDurability) -> LedgerKey {
        let mut cid = [0u8; 32];
        cid[0] = 7;
        LedgerKeys::contract_data(&cid, &ScVal::U32(2), durability)
    }

    #[test]
    fn at_risk_entries_are_included() {
        let key = data_key(ContractDataDurability::Persistent);
        let observations = vec![(
            key,
            EntryTtl {
                current_ledger: 100,
                live_until_ledger_seq: Some(500),
            },
        )];
        let plan = planner().plan_extend(&observations, 100).expect("plan");
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].kind, OperationKind::Extend);
        assert_eq!(plan.entries[0].durability, Some(Durability::Persistent));
        assert_eq!(plan.reference_ledger, 100);
    }

    #[test]
    fn healthy_entries_are_excluded() {
        let key = data_key(ContractDataDurability::Persistent);
        let observations = vec![(
            key,
            EntryTtl {
                current_ledger: 100,
                live_until_ledger_seq: Some(100_000),
            },
        )];
        let plan = planner().plan_extend(&observations, 100).expect("plan");
        assert!(plan.is_empty());
    }

    #[test]
    fn entries_without_ttl_are_ignored_by_extend() {
        let key = data_key(ContractDataDurability::Temporary);
        let observations = vec![(
            key,
            EntryTtl {
                current_ledger: 100,
                live_until_ledger_seq: None,
            },
        )];
        let plan = planner().plan_extend(&observations, 100).expect("plan");
        assert!(plan.is_empty());
    }

    #[test]
    fn extend_to_is_clamped_to_network_max() {
        let planner = Planner::new(
            constants(),
            RiskWindow {
                alert_horizon_ledgers: u64::from(constants().max_entry_ttl) * 2,
            },
            "Test",
        );
        assert_eq!(
            planner.risk_window().extend_to_ledgers(&constants()),
            constants().max_entry_ttl
        );
    }

    #[test]
    fn restore_plan_includes_every_observed_archived_entry() {
        let key = data_key(ContractDataDurability::Persistent);
        let observations = vec![(
            key,
            ArchivedEntryInfo {
                current_ledger: 100,
                archived: true,
            },
        )];
        let plan = planner().plan_restore(&observations, 100).expect("plan");
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].kind, OperationKind::Restore);
    }

    #[test]
    fn ttl_verdict_reflects_expiry_boundary() {
        let ttl_entry = stellar_xdr::TtlEntry {
            key_hash: stellar_xdr::Hash([9u8; 32]),
            live_until_ledger_seq: 1_000,
        };
        assert_eq!(
            Planner::classify_ttl_entry(&ttl_entry, 999),
            TtlVerdict::Live { remaining: 1 }
        );
        assert_eq!(
            Planner::classify_ttl_entry(&ttl_entry, 1_000),
            TtlVerdict::Expired
        );
        assert_eq!(
            Planner::classify_ttl_entry(&ttl_entry, 1_500),
            TtlVerdict::Expired
        );
    }
}
