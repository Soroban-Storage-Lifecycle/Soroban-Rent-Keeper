//! TTL model and risk-window arithmetic for Soroban state archival.
//!
//! All quantities are in ledgers unless stated otherwise. The TTL of an entry is
//! `live_until_ledger_seq - current_ledger_seq`; an entry whose TTL has reached
//! zero is evicted (persistent/temporary entries get archived by state
//! archival). Extension works the way the protocol defines it for
//! `ExtendFootprintTtl`: the footprint entries are bumped *to* `extend_to`
//! ledgers of remaining TTL (clamped by the network `max_entry_ttl` for
//! persistent entries), not by `extend_to` additional ledgers.

/// Protocol defaults observed on Stellar networks (protocol 22+).
///
/// * A ledger closes roughly every 5 seconds.
/// * `max_entry_ttl` on public networks is 6,312,000 ledgers (~1 year).
/// * `min_persistent_ttl` and `min_temporary_ttl` are 409,600 ledgers (~24 days).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlConstants {
    /// Approximate number of seconds per ledger.
    pub seconds_per_ledger: u64,
    /// Network `max_entry_ttl` setting in ledgers.
    pub max_entry_ttl: u32,
    /// Network `min_persistent_ttl` setting in ledgers.
    pub min_persistent_ttl: u32,
    /// Network `min_temporary_ttl` setting in ledgers.
    pub min_temporary_ttl: u32,
}

impl TtlConstants {
    /// Settings currently used by Stellar public networks.
    #[must_use]
    pub const fn stellar_public() -> Self {
        Self {
            seconds_per_ledger: 5,
            max_entry_ttl: 6_312_000,
            min_persistent_ttl: 409_600,
            min_temporary_ttl: 409_600,
        }
    }
}

impl Default for TtlConstants {
    fn default() -> Self {
        Self::stellar_public()
    }
}

/// Observed TTL state of one extendable ledger entry at some ledger height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryTtl {
    /// Ledger at which the snapshot was taken.
    pub current_ledger: u32,
    /// Ledger after which the entry is no longer live. `None` for entries
    /// without a TTL (e.g. config settings).
    pub live_until_ledger_seq: Option<u32>,
}

impl EntryTtl {
    /// Remaining ledgers of TTL at the snapshot height, if the entry has a TTL.
    #[must_use]
    pub fn ttl_ledgers(&self) -> Option<u64> {
        self.live_until_ledger_seq
            .map(|live_until| u64::from(live_until) - u64::from(self.current_ledger))
    }

    /// Ledger at which the entry expires, if it has a TTL.
    #[must_use]
    pub fn expiry_ledger(&self) -> Option<u32> {
        self.live_until_ledger_seq
    }
}
