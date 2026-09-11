//! TTL model and risk-window arithmetic for Soroban state archival.
//!
//! All quantities are in ledgers unless stated otherwise. The TTL of an entry is
//! `live_until_ledger_seq - current_ledger_seq`; an entry whose TTL has reached
//! zero is evicted (persistent/temporary entries get archived by state
//! archival). Extension works the way the protocol defines it for
//! `ExtendFootprintTtl`: the footprint entries are bumped *to* `extend_to`
//! ledgers of remaining TTL (clamped by the network `max_entry_ttl` for
//! persistent entries), not by `extend_to` additional ledgers.

use stellar_xdr::ContractDataDurability;

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

/// Snapshot of the archived/dead side of an entry, used by restore planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchivedEntryInfo {
    /// Ledger at which the snapshot was taken.
    pub current_ledger: u32,
    /// True when the RPC `getLedgerEntries` response contained no live entry.
    pub archived: bool,
}

impl ArchivedEntryInfo {
    /// True when the entry is (or was at snapshot time) in archived state.
    #[must_use]
    pub fn is_archived(&self) -> bool {
        self.archived
    }
}

/// The durability class of an entry, re-exported conceptually for planners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Temporary entry: cheap, short minimum TTL, no clamping on extension.
    Temporary,
    /// Persistent entry: rent-backed, clamped to `max_entry_ttl` on extension.
    Persistent,
}

impl Durability {
    /// Maps an XDR durability onto the planner-facing enum.
    #[must_use]
    pub const fn from_xdr(durability: ContractDataDurability) -> Self {
        match durability {
            ContractDataDurability::Temporary => Self::Temporary,
            ContractDataDurability::Persistent => Self::Persistent,
        }
    }

    /// Protocol minimum TTL for this durability class.
    #[must_use]
    pub const fn min_ttl(&self, constants: &TtlConstants) -> u32 {
        match self {
            Self::Temporary => constants.min_temporary_ttl,
            Self::Persistent => constants.min_persistent_ttl,
        }
    }

    /// Human-readable name matching the XDR variant.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Temporary => "Temporary",
            Self::Persistent => "Persistent",
        }
    }
}

/// How many ledgers of headroom the keeper tries to keep above the alert line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskWindow {
    /// Extend any entry whose remaining TTL has dropped to or below this value.
    pub alert_horizon_ledgers: u64,
}

impl RiskWindow {
    /// A window expressed in (approximate) days, using 5s ledgers.
    #[must_use]
    pub fn from_days(days: f64) -> Self {
        let ledgers = (days * 86_400.0 / 5.0).ceil();
        // Inputs above u32::MAX or below zero are nonsensical; clamp them. The
        // clamps guarantee the value fits, so the cast cannot truncate.
        let alert_horizon_ledgers = if ledgers < 0.0 {
            0
        } else if ledgers >= f64::from(u32::MAX) {
            u64::from(u32::MAX)
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                ledgers as u64
            }
        };
        Self {
            alert_horizon_ledgers,
        }
    }

    /// True when the entry's remaining TTL is at or below the alert horizon.
    ///
    /// Entries without a TTL (config settings, accounts) are never at risk.
    #[must_use]
    pub fn is_at_risk(&self, ttl: &EntryTtl) -> bool {
        match ttl.ttl_ledgers() {
            Some(remaining) => remaining <= self.alert_horizon_ledgers,
            None => false,
        }
    }

    /// The `extend_to` value (in TTL ledgers) to use for an extension, capped
    /// at the network `max_entry_ttl` so persistent entries stay valid.
    #[must_use]
    pub fn extend_to_ledgers(&self, constants: &TtlConstants) -> u32 {
        u32::try_from(self.alert_horizon_ledgers)
            .unwrap_or(constants.max_entry_ttl)
            .min(constants.max_entry_ttl)
    }

    /// Seconds of wall-clock headroom before expiry, given `seconds_per_ledger`.
    #[must_use]
    pub fn seconds_of_headroom(&self, constants: &TtlConstants, ttl: &EntryTtl) -> Option<u64> {
        ttl.ttl_ledgers().map(|remaining| {
            remaining.saturating_sub(self.alert_horizon_ledgers) * constants.seconds_per_ledger
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_is_difference_of_ledger_heights() {
        let ttl = EntryTtl {
            current_ledger: 1_000_000,
            live_until_ledger_seq: Some(1_000_100),
        };
        assert_eq!(ttl.ttl_ledgers(), Some(100));
        assert_eq!(ttl.expiry_ledger(), Some(1_000_100));
    }

    #[test]
    fn entries_without_ttl_are_never_at_risk() {
        let window = RiskWindow::from_days(1.0);
        let ttl = EntryTtl {
            current_ledger: 500,
            live_until_ledger_seq: None,
        };
        assert!(ttl.ttl_ledgers().is_none());
        assert!(!window.is_at_risk(&ttl));
    }

    #[test]
    fn one_day_window_is_about_17280_ledgers() {
        let window = RiskWindow::from_days(1.0);
        assert_eq!(window.alert_horizon_ledgers, 17_280);
    }

    #[test]
    fn at_risk_when_ttl_equals_or_drops_below_horizon() {
        let window = RiskWindow {
            alert_horizon_ledgers: 100,
        };
        let boundary = EntryTtl {
            current_ledger: 10_000,
            live_until_ledger_seq: Some(10_100),
        };
        let below = EntryTtl {
            current_ledger: 10_000,
            live_until_ledger_seq: Some(10_050),
        };
        let above = EntryTtl {
            current_ledger: 10_000,
            live_until_ledger_seq: Some(10_101),
        };
        assert!(window.is_at_risk(&boundary));
        assert!(window.is_at_risk(&below));
        assert!(!window.is_at_risk(&above));
    }

    #[test]
    fn extend_to_is_clamped_to_network_max() {
        let constants = TtlConstants::stellar_public();
        let huge = RiskWindow {
            alert_horizon_ledgers: u64::from(constants.max_entry_ttl) + 5,
        };
        assert_eq!(huge.extend_to_ledgers(&constants), constants.max_entry_ttl);

        let normal = RiskWindow::from_days(30.0);
        assert_eq!(normal.extend_to_ledgers(&constants), 518_400);
    }

    #[test]
    fn headroom_uses_seconds_per_ledger() {
        let constants = TtlConstants::stellar_public();
        let window = RiskWindow {
            alert_horizon_ledgers: 100,
        };
        let ttl = EntryTtl {
            current_ledger: 1,
            live_until_ledger_seq: Some(201),
        };
        assert_eq!(window.seconds_of_headroom(&constants, &ttl), Some(500));
    }

    #[test]
    fn durability_names_match_xdr() {
        assert_eq!(
            Durability::from_xdr(ContractDataDurability::Persistent).name(),
            "Persistent"
        );
        assert_eq!(
            Durability::from_xdr(ContractDataDurability::Temporary).name(),
            "Temporary"
        );
    }
}
