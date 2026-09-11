//! Translates watch specs into concrete ledger keys, and implements the poll
//! loop that observes, plans, and submits extends.

use rentkeeper_core::ledger_keys::LedgerKeys;
use rentkeeper_core::plan::{ArchivalPlan, OperationKind};
use rentkeeper_core::planner::Planner;
use rentkeeper_core::provider::{EntryState, Observation, SorobanProvider};
use rentkeeper_core::ttl::EntryTtl;
use rentkeeper_core::tx::{FeePayer, TxBuilder};
use stellar_xdr::{ContractDataDurability, Hash, LedgerKey, ReadXdr, ScVal};

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

/// Result of one poll cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleReport {
    /// Ledger height of the observation snapshot.
    pub observed_ledger: u32,
    /// Entries that were at or below the risk window.
    pub entries_at_risk: usize,
    /// Whether an extend transaction was submitted this cycle.
    pub extend_submitted: bool,
}

/// Outcome of submitting one transaction to the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionOutcome {
    /// Node accepted the transaction (pending or duplicate hash).
    Accepted,
    /// Node rejected the transaction (kept for callers/tests that classify
    /// node responses; the current happy-path submit maps errors to Err).
    #[allow(dead_code)]
    Rejected,
}

/// Runs one full observe-plan-submit cycle.
///
/// # Errors
/// Errors on RPC failures and on transaction build/sign problems. Entry-level
/// anomalies (e.g. entries needing restore) are surfaced in the report but do
/// not fail the cycle: the daemon's job is extends, and restore is delegated
/// to the `restore-planner` operator flow.
pub async fn run_cycle(
    provider: &SorobanProvider,
    config: &ValidConfig,
    payer: &FeePayer,
) -> Result<CycleReport, KeeperError> {
    let keys = resolve_watch_keys(config)?;
    if keys.is_empty() {
        return Err(KeeperError::InvalidWatch(
            "no watch keys resolved from configuration".to_string(),
        ));
    }

    let observations = provider
        .observe_entries(&keys)
        .await
        .map_err(|e| KeeperError::Rpc(e.to_string()))?;
    let observed_ledger = observations
        .first()
        .map(|o| o.current_ledger)
        .unwrap_or_default();

    // Separate live entries (extendable) from ones needing restore, which the
    // daemon logs and skips: restoring needs operator sign-off on fees.
    let mut extendable: Vec<(LedgerKey, EntryTtl)> = Vec::new();
    for (key, observation) in keys.iter().zip(observations.iter()) {
        match &observation.entry {
            EntryState::Live(ttl) => extendable.push((key.clone(), *ttl)),
            EntryState::ExpiredButPresent(_) | EntryState::Archived(_) => {
                let rendered = LedgerKeys::render(key).unwrap_or_else(|_| "<unrenderable>".into());
                tracing::warn!(entry = %rendered, "entry needs restore; skipped by daemon");
            }
        }
    }

    let planner = Planner::new(
        config.constants,
        config.risk_window,
        &config.network_passphrase,
    );
    let plan = planner
        .plan_extend(&extendable, observed_ledger)
        .map_err(|e| KeeperError::Transaction(e.to_string()))?;

    if plan.is_empty() {
        return Ok(CycleReport {
            observed_ledger,
            entries_at_risk: 0,
            extend_submitted: false,
        });
    }

    let builder = TxBuilder::new(&config.network_passphrase);
    let seq_num = fetch_account_sequence(provider, &payer.account_id_strkey())
        .await?
        .wrapping_add(1);
    let envelope = builder
        .build_signed(&plan, payer.signing_key(), seq_num)
        .map_err(|e| KeeperError::Transaction(e.to_string()))?;

    let outcome = submit_extend(provider, &envelope).await?;
    Ok(CycleReport {
        observed_ledger,
        entries_at_risk: plan.len(),
        extend_submitted: matches!(outcome, SubmissionOutcome::Accepted),
    })
}

/// Submits a signed extend envelope, tolerating duplicate submissions.
///
/// # Errors
/// Errors on RPC transport failures.
pub async fn submit_extend(
    provider: &SorobanProvider,
    envelope: &stellar_xdr::TransactionEnvelope,
) -> Result<SubmissionOutcome, KeeperError> {
    let hash = provider
        .send_transaction(envelope)
        .await
        .map_err(|e| KeeperError::Rpc(e.to_string()))?;
    tracing::info!(tx_hash = ?hash, "extend transaction accepted");
    Ok(SubmissionOutcome::Accepted)
}

async fn fetch_account_sequence(
    provider: &SorobanProvider,
    account_id_strkey: &str,
) -> Result<i64, KeeperError> {
    let entry = provider
        .get_account(account_id_strkey)
        .await
        .map_err(|e| KeeperError::Rpc(format!("get_account: {e}")))?;
    Ok(entry.seq_num.0)
}

/// Classifies an observation (used by tests and future metrics wiring).
#[must_use]
#[allow(dead_code)]
pub fn is_extendable(observation: &Observation) -> bool {
    matches!(observation.entry, EntryState::Live(_))
}

/// Convenience wrapper producing the operation kind the daemon submits.
#[must_use]
#[allow(dead_code)]
pub const fn daemon_operation() -> OperationKind {
    OperationKind::Extend
}

/// Marker for plan construction parity with the planner.
#[must_use]
#[allow(dead_code)]
pub fn empty_plan(passphrase: &str) -> ArchivalPlan {
    ArchivalPlan {
        network_passphrase: passphrase.to_string(),
        reference_ledger: 0,
        extend_to: 0,
        entries: vec![],
    }
}

#[allow(unused_imports)]
use Hash as _HashWitness;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_config;
    use std::path::PathBuf;

    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn test_config(watch: &str) -> ValidConfig {
        let contents = format!(
            r#"
rpc_url = "https://soroban-testnet.stellar.org:443"
network_passphrase = "Test SDF Network ; September 2015"
secret_key = "SBFIJNQVTU3QZGZSVAHBQFAKHRGFNIHQMIVJJSGV7HRPC7CLBR7QZL7VYP"
{watch}
"#
        );
        // Tests run in parallel: every caller gets its own directory so they
        // cannot overwrite each other's config file.
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rentkeeper-watcher-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path: PathBuf = dir.join("config.toml");
        std::fs::write(&path, &contents).expect("write");
        load_config(&path).expect("valid config")
    }

    #[test]
    fn instance_watch_resolves_to_contract_data_key() {
        let config = test_config(
            format!("[[watch]]\ntype = \"instance\"\ncontract_id = \"{CONTRACT}\"\n").as_str(),
        );
        let keys = resolve_watch_keys(&config).expect("keys");
        assert_eq!(keys.len(), 1);
        assert!(matches!(keys[0], LedgerKey::ContractData(_)));
    }

    #[test]
    fn code_watch_resolves_to_contract_code_key() {
        let config = test_config(
            "[[watch]]\ntype = \"contract_code\"\nwasm_hash = \"aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd\"\n",
        );
        let keys = resolve_watch_keys(&config).expect("keys");
        assert_eq!(keys.len(), 1);
        match &keys[0] {
            LedgerKey::ContractCode(code) => {
                assert_eq!(code.hash.0[0], 0xaa);
                assert_eq!(code.hash.0[31], 0xdd);
            }
            other => panic!("expected code key, got {other:?}"),
        }
    }

    #[test]
    fn data_key_watch_roundtrips_scval() {
        // ScVal::U32(7): tag SCV_U32 (=3) + big-endian uint32, base64-encoded.
        let config = test_config(format!(
            "[[watch]]\ntype = \"data_key\"\ncontract_id = \"{CONTRACT}\"\nkey_xdr = \"AAAAAwAAAAc=\"\ndurability = \"temporary\"\n"
        ).as_str());
        let keys = resolve_watch_keys(&config).expect("keys");
        assert_eq!(keys.len(), 1);
        match &keys[0] {
            LedgerKey::ContractData(data) => {
                assert_eq!(data.durability, ContractDataDurability::Temporary);
                assert_eq!(data.key, ScVal::U32(7));
            }
            other => panic!("expected data key, got {other:?}"),
        }
    }

    #[test]
    fn bad_contract_id_is_rejected() {
        // Build a config directly, bypassing file validation, to exercise the
        // watcher's own key-resolution error path.
        let config = ValidConfig {
            rpc_url: "https://localhost".to_string(),
            network_passphrase: "Test".to_string(),
            secret_key: "SBFIJNQVTU3QZGZSVAHBQFAKHRGFNIHQMIVJJSGV7HRPC7CLBR7QZL7VYP".to_string(),
            watch: vec![WatchSpec::Instance {
                contract_id: "nonsense".to_string(),
            }],
            poll_interval: std::time::Duration::from_secs(1),
            risk_window: rentkeeper_core::RiskWindow {
                alert_horizon_ledgers: 100,
            },
            metrics_port: None,
            constants: rentkeeper_core::TtlConstants::stellar_public(),
        };
        assert!(matches!(
            resolve_watch_keys(&config),
            Err(KeeperError::InvalidWatch(_))
        ));
    }

    #[test]
    fn instance_key_is_the_reserved_symbol() {
        assert_eq!(instance_key(), ScVal::LedgerKeyContractInstance);
    }

    #[test]
    fn extendable_classification_matches_state() {
        let live = Observation {
            current_ledger: 1,
            entry: EntryState::Live(EntryTtl {
                current_ledger: 1,
                live_until_ledger_seq: Some(10),
            }),
        };
        let archived = Observation {
            current_ledger: 1,
            entry: EntryState::Archived(rentkeeper_core::ttl::ArchivedEntryInfo {
                current_ledger: 1,
                archived: true,
            }),
        };
        assert!(is_extendable(&live));
        assert!(!is_extendable(&archived));
        assert_eq!(daemon_operation(), OperationKind::Extend);
    }

    #[test]
    fn empty_plan_helper_builds_placeholder() {
        let plan = empty_plan("Test");
        assert!(plan.is_empty());
        assert_eq!(plan.network_passphrase, "Test");
    }
}
