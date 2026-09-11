//! Plan model shared by the rent keeper daemon and the restore planner CLI.
//!
//! A plan is a pure data structure: which ledger keys to touch, what kind of
//! operation (extend or restore), and the target TTL. The transaction builder
//! turns plans into signed Soroban transactions.

use stellar_xdr::LedgerKey;

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
