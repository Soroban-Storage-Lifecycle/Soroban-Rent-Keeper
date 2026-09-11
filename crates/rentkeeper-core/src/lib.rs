//! Shared ledger/state-archival planning, risk-window, and Soroban
//! transaction-building primitives for the Soroban Rent Keeper framework.

pub mod error;
pub mod ledger_keys;
pub mod plan;
pub mod planner;
pub mod provider;
pub mod ttl;
pub mod tx;

pub use error::RentkeeperError;
pub use ledger_keys::LedgerKeys;
pub use plan::{ArchivalPlan, OperationKind, PlanEntry};
pub use planner::{Planner, TtlVerdict};
pub use provider::{EntryState, Observation, SorobanProvider};
pub use ttl::{EntryTtl, RiskWindow, TtlConstants};
pub use tx::{TxBuilder, DEFAULT_BASE_FEE};
