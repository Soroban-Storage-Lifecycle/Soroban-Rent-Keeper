//! Plan model shared by the rent keeper daemon and the restore planner CLI.
//!
//! A plan is a pure data structure: which ledger keys to touch, what kind of
//! operation (extend or restore), and the target TTL. The transaction builder
//! turns plans into signed Soroban transactions.

use stellar_xdr::{ContractDataDurability, LedgerKey};

use crate::ttl::EntryTtl;

/// The kind of archival operation a plan entry requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// `ExtendFootprintTtl`: bump live entries to a longer TTL.
    Extend,
    /// `RestoreFootprint`: bring archived (expired) entries back to life.
    Restore,
}

impl OperationKind {
    /// Stable machine-readable name used in JSON plans.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Extend => "extend",
            Self::Restore => "restore",
        }
    }
}

/// One entry that a plan wants to touch, with its observed TTL state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    /// The ledger entry to include in the operation footprint.
    pub key: LedgerKey,
    /// Base64 XDR rendering of `key` for stable serialization in JSON plans.
    pub key_xdr: String,
    /// Whether the entry needs extension or restoration.
    pub kind: OperationKind,
    /// Durability class for contract data entries; `None` for code/config.
    pub durability: Option<crate::ttl::Durability>,
    /// Observed TTL state at plan time.
    pub ttl: EntryTtl,
}

impl PlanEntry {
    /// Remaining TTL in ledgers at plan time, if the entry carries a TTL.
    #[must_use]
    pub fn remaining_ttl(&self) -> Option<u64> {
        self.ttl.ttl_ledgers()
    }
}

/// A batched set of entries to extend or restore in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivalPlan {
    /// Network passphrase the plan was built for.
    pub network_passphrase: String,
    /// Ledger height the observations were made at.
    pub reference_ledger: u32,
    /// Target TTL (in ledgers) the plan extends entries to.
    pub extend_to: u32,
    /// Entries to touch.
    pub entries: Vec<PlanEntry>,
}

impl ArchivalPlan {
    /// Number of entries in the plan.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the plan touches nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Count of entries by operation kind.
    #[must_use]
    pub fn count_kind(&self, kind: OperationKind) -> usize {
        self.entries.iter().filter(|e| e.kind == kind).count()
    }

    /// The mixed footprint implied by the plan: all entries live in
    /// `read_write` because both extend and restore mutate TTLs.
    #[must_use]
    pub fn footprint(&self) -> Vec<LedgerKey> {
        self.entries.iter().map(|e| e.key.clone()).collect()
    }
}

/// Serializes a plan to pretty JSON (base64 key XDRs inside).
///
/// # Errors
/// Returns an error if JSON serialization fails.
pub fn plan_to_json(plan: &ArchivalPlan) -> Result<String, crate::error::RentkeeperError> {
    serde_json::to_string_pretty(plan)
        .map_err(|e| crate::error::RentkeeperError::Config(format!("json: {e}")))
}

/// Rebuilds a plan from JSON produced by [`plan_to_json`].
///
/// # Errors
/// Returns an error if JSON deserialization fails.
pub fn plan_from_json(json: &str) -> Result<ArchivalPlan, crate::error::RentkeeperError> {
    serde_json::from_str(json)
        .map_err(|e| crate::error::RentkeeperError::Config(format!("json: {e}")))
}

/// Allows plans to be serialized to JSON files.
impl serde::Serialize for ArchivalPlan {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ArchivalPlan", 4)?;
        s.serialize_field("network_passphrase", &self.network_passphrase)?;
        s.serialize_field("reference_ledger", &self.reference_ledger)?;
        s.serialize_field("extend_to", &self.extend_to)?;
        let entries: Vec<serde_json::Value> = self
            .entries
            .iter()
            .map(|e| {
                let durability = e.durability.as_ref().map(crate::ttl::Durability::name);
                serde_json::json!({
                    "key_xdr": e.key_xdr,
                    "operation": e.kind.as_str(),
                    "durability": durability,
                    "current_ledger": e.ttl.current_ledger,
                    "live_until_ledger_seq": e.ttl.live_until_ledger_seq,
                })
            })
            .collect();
        s.serialize_field("entries", &entries)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for ArchivalPlan {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct RawEntry {
            key_xdr: String,
            operation: String,
            #[serde(default)]
            current_ledger: u32,
            #[serde(default)]
            live_until_ledger_seq: Option<u32>,
        }
        #[derive(serde::Deserialize)]
        struct RawPlan {
            network_passphrase: String,
            reference_ledger: u32,
            extend_to: u32,
            #[serde(default)]
            entries: Vec<RawEntry>,
        }

        use stellar_xdr::{Limits, ReadXdr};
        let raw = RawPlan::deserialize(deserializer)?;
        let mut entries = Vec::with_capacity(raw.entries.len());
        for e in raw.entries {
            let key = LedgerKey::from_xdr_base64(e.key_xdr.as_bytes(), Limits::none())
                .map_err(serde::de::Error::custom)?;
            let kind = match e.operation.as_str() {
                "extend" => OperationKind::Extend,
                "restore" => OperationKind::Restore,
                other => {
                    return Err(serde::de::Error::custom(format!(
                        "unknown operation kind: {other}"
                    )))
                }
            };
            // Durability is derived from the decoded key itself, so plans stay
            // self-consistent even if hand-edited.
            let durability = match &key {
                LedgerKey::ContractData(d) => Some(crate::ttl::Durability::from_xdr(d.durability)),
                _ => None,
            };
            entries.push(PlanEntry {
                key_xdr: e.key_xdr,
                key,
                kind,
                durability,
                ttl: EntryTtl {
                    current_ledger: e.current_ledger,
                    live_until_ledger_seq: e.live_until_ledger_seq,
                },
            });
        }
        Ok(ArchivalPlan {
            network_passphrase: raw.network_passphrase,
            reference_ledger: raw.reference_ledger,
            extend_to: raw.extend_to,
            entries,
        })
    }
}

/// Convenience alias used by callers that only care about the XDR durability.
#[must_use]
pub fn durability_from_xdr(d: ContractDataDurability) -> crate::ttl::Durability {
    crate::ttl::Durability::from_xdr(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_keys::LedgerKeys;
    use stellar_xdr::{Limits, ReadXdr, ScVal};

    fn sample_key() -> (LedgerKey, String) {
        let mut cid = [0u8; 32];
        cid[31] = 1;
        let key =
            LedgerKeys::contract_data(&cid, &ScVal::U32(1), ContractDataDurability::Persistent);
        let rendered = LedgerKeys::render(&key).expect("render");
        (key, rendered)
    }

    fn sample_plan() -> ArchivalPlan {
        let (key, key_xdr) = sample_key();
        ArchivalPlan {
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            reference_ledger: 100,
            extend_to: 518_400,
            entries: vec![PlanEntry {
                key,
                key_xdr,
                kind: OperationKind::Extend,
                durability: Some(crate::ttl::Durability::Persistent),
                ttl: EntryTtl {
                    current_ledger: 100,
                    live_until_ledger_seq: Some(200),
                },
            }],
        }
    }

    #[test]
    fn plan_json_roundtrip_preserves_entries() {
        let plan = sample_plan();
        let json = plan_to_json(&plan).expect("serialize");
        let back = plan_from_json(&json).expect("deserialize");
        assert_eq!(back.network_passphrase, plan.network_passphrase);
        assert_eq!(back.reference_ledger, plan.reference_ledger);
        assert_eq!(back.extend_to, plan.extend_to);
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].key, plan.entries[0].key);
        assert_eq!(back.entries[0].kind, OperationKind::Extend);
        assert_eq!(
            back.entries[0].durability,
            Some(crate::ttl::Durability::Persistent)
        );
    }

    #[test]
    fn plan_json_rejects_unknown_operation() {
        let plan = sample_plan();
        let json = plan_to_json(&plan).expect("serialize");
        let mut value: serde_json::Value = serde_json::from_str(&json).expect("value");
        value["entries"][0]["operation"] = serde_json::Value::String("teleport".into());
        let bad = serde_json::to_string(&value).expect("restring");
        assert!(plan_from_json(&bad).is_err());
    }

    #[test]
    fn footprint_contains_every_entry() {
        let plan = sample_plan();
        assert_eq!(plan.footprint().len(), 1);
        assert_eq!(plan.count_kind(OperationKind::Extend), 1);
        assert_eq!(plan.count_kind(OperationKind::Restore), 0);
        assert!(!plan.is_empty());
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn remaining_ttl_reads_through() {
        let plan = sample_plan();
        assert_eq!(plan.entries[0].remaining_ttl(), Some(100));
    }

    #[test]
    fn decoded_xdr_key_roundtrips() {
        let (_, key_xdr) = sample_key();
        let key = LedgerKey::from_xdr_base64(key_xdr.as_bytes(), Limits::none()).expect("decode");
        let re = LedgerKeys::render(&key).expect("render");
        assert_eq!(re, key_xdr);
    }
}
