//! `restore-planner`: inspects archived Soroban contracts and generates
//! restore footprints, recovery plans, and `RestoreFootprint` transactions.

mod cli;

use clap::Parser as _;
use rentkeeper_core::ledger_keys::LedgerKeys;
use rentkeeper_core::plan::{ArchivalPlan, OperationKind, PlanEntry};
use rentkeeper_core::planner::Planner;
use rentkeeper_core::ttl::{ArchivedEntryInfo, Durability, EntryTtl, RiskWindow};
use stellar_xdr::{ContractDataDurability, LedgerKey, ScVal};

use cli::{Cli, CliError, Command};

fn init_tracing(filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(filter)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(&cli.log_filter);

    let code = match run(cli).await {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<(), CliError> {
    match &cli.command {
        Command::Inspect {
            contract,
            key_xdr,
            durability,
            include_code,
            wasm_hash,
        } => {
            let _ = include_code; // presence of --wasm-hash drives code inspection
            let provider = cli::connect(&cli.connect)?;
            let mut keys: Vec<LedgerKey> = Vec::new();

            let contract_bytes = cli::contract_id_bytes(contract)?;
            match key_xdr {
                Some(xdr) => {
                    let key = cli::parse_scval(xdr)?;
                    let durability = cli::parse_durability(durability)?;
                    keys.push(LedgerKeys::contract_data(&contract_bytes, &key, durability));
                }
                None => {
                    // Instance entry is always inspectable without extra args.
                    keys.push(LedgerKeys::contract_data(
                        &contract_bytes,
                        &instance_key(),
                        ContractDataDurability::Persistent,
                    ));
                }
            }

            if let Some(hash) = wasm_hash {
                let bytes = cli::wasm_hash_bytes(hash)?;
                keys.push(LedgerKeys::contract_code(&bytes));
            }

            let observations = provider
                .observe_entries(&keys)
                .await
                .map_err(|e| CliError::Operation(e.to_string()))?;

            println!(
                "{:<12} {:<11} {:>18} {:>12}",
                "KIND", "DURABILITY", "LIVE_UNTIL", "STATUS"
            );
            for (key, observation) in keys.iter().zip(observations.iter()) {
                print_inspection_row(key, observation);
            }
            Ok(())
        }

        Command::PlanRestore {
            contract,
            key_xdrs,
            durability,
            ttl_days,
            out,
        } => {
            let contract_bytes = cli::contract_id_bytes(contract)?;
            let durability = cli::parse_durability(durability)?;
            let mut keys = Vec::new();
            for xdr in key_xdrs {
                let key = cli::parse_scval(xdr)?;
                keys.push(LedgerKeys::contract_data(&contract_bytes, &key, durability));
            }

            let provider = cli::connect(&cli.connect)?;
            let observations = provider
                .observe_entries(&keys)
                .await
                .map_err(|e| CliError::Operation(e.to_string()))?;
            let current_ledger = observations
                .first()
                .map(|o| o.current_ledger)
                .unwrap_or_default();

            // Confirm the entries actually need a restore; refuse otherwise.
            let archived: Vec<(LedgerKey, ArchivedEntryInfo)> = keys
                .iter()
                .zip(observations.iter())
                .filter(|(_, o)| o.needs_restore())
                .map(|(k, o)| {
                    (
                        k.clone(),
                        ArchivedEntryInfo {
                            current_ledger: o.current_ledger,
                            archived: true,
                        },
                    )
                })
                .collect();
            if archived.is_empty() {
                return Err(CliError::Invalid(
                    "none of the given entries are archived; nothing to restore".to_string(),
                ));
            }

            let planner = Planner::new(
                cli::constants(),
                RiskWindow {
                    alert_horizon_ledgers: u64::from(cli::days_to_extend_to(*ttl_days)),
                },
                &cli.connect.network_passphrase,
            );
            let mut plan = planner
                .plan_restore(&archived, current_ledger)
                .map_err(|e| CliError::Operation(e.to_string()))?;
            plan.extend_to = cli::days_to_extend_to(*ttl_days);
            plan.entries.iter_mut().for_each(|e| {
                e.ttl = EntryTtl {
                    current_ledger,
                    live_until_ledger_seq: None,
                };
            });

            println!(
                "restore plan: {} entr(y/ies), target TTL {} ledgers, reference ledger {}",
                plan.len(),
                plan.extend_to,
                plan.reference_ledger
            );
            cli::emit_plan(&plan, out.as_ref())
        }

        Command::PlanExtend {
            contract,
            key_xdrs,
            durability,
            ttl_days,
            out,
        } => {
            let contract_bytes = cli::contract_id_bytes(contract)?;
            let durability = cli::parse_durability(durability)?;
            let mut keys = Vec::new();
            for xdr in key_xdrs {
                let key = cli::parse_scval(xdr)?;
                keys.push(LedgerKeys::contract_data(&contract_bytes, &key, durability));
            }

            let provider = cli::connect(&cli.connect)?;
            let observations = provider
                .observe_entries(&keys)
                .await
                .map_err(|e| CliError::Operation(e.to_string()))?;
            let current_ledger = observations
                .first()
                .map(|o| o.current_ledger)
                .unwrap_or_default();

            // Direct construction: plan-extend is operator-driven, so extend
            // every requested live entry regardless of the risk window.
            let extend_to = cli::days_to_extend_to(*ttl_days);
            let mut entries = Vec::new();
            for (key, observation) in keys.iter().zip(observations.iter()) {
                let ttl = observation.as_entry_ttl();
                if ttl.live_until_ledger_seq.is_none() {
                    let rendered =
                        LedgerKeys::render(key).unwrap_or_else(|_| "<unrenderable>".into());
                    return Err(CliError::Invalid(format!(
                        "entry {rendered} is not live (needs restore, not extend)"
                    )));
                }
                entries.push(PlanEntry {
                    key_xdr: LedgerKeys::render(key)
                        .map_err(|e| CliError::Operation(e.to_string()))?,
                    key: key.clone(),
                    kind: OperationKind::Extend,
                    durability: durability_of(key),
                    ttl,
                });
            }

            let plan = ArchivalPlan {
                network_passphrase: cli.connect.network_passphrase.clone(),
                reference_ledger: current_ledger,
                extend_to,
                entries,
            };
            println!(
                "extend plan: {} entr(y/ies), target TTL {} ledgers, reference ledger {}",
                plan.len(),
                plan.extend_to,
                plan.reference_ledger
            );
            cli::emit_plan(&plan, out.as_ref())
        }

        Command::ShowPlan { plan: path } => {
            let plan = cli::read_plan(path)?;
            println!("network:       {}", plan.network_passphrase);
            println!("reference ledger: {}", plan.reference_ledger);
            println!(
                "target TTL:    {} ledgers (~{:.1} days at 5s/ledger)",
                plan.extend_to,
                f64::from(plan.extend_to) * 5.0 / 86_400.0
            );
            println!("entries:       {}", plan.len());
            println!("  extend:  {}", plan.count_kind(OperationKind::Extend));
            println!("  restore: {}", plan.count_kind(OperationKind::Restore));
            for (i, entry) in plan.entries.iter().enumerate() {
                println!(
                    "  [{i}] {} {} ttl={:?}",
                    entry.kind.as_str(),
                    entry
                        .durability
                        .as_ref()
                        .map(Durability::name)
                        .unwrap_or("n/a"),
                    entry.remaining_ttl()
                );
                println!("       key: {}", entry.key_xdr);
            }
            Ok(())
        }
    }
}

fn print_inspection_row(key: &LedgerKey, observation: &rentkeeper_core::Observation) {
    let kind = match key {
        LedgerKey::ContractData(_) => "contract_data",
        LedgerKey::ContractCode(_) => "contract_code",
        LedgerKey::Ttl(_) => "ttl",
        _ => "other",
    };
    let durability = durability_of(key)
        .map(|d| d.name().to_string())
        .unwrap_or_else(|| "-".to_string());
    let (live_until, status) = match &observation.entry {
        rentkeeper_core::EntryState::Live(ttl) => (
            ttl.live_until_ledger_seq
                .map(|l| l.to_string())
                .unwrap_or_else(|| "none".to_string()),
            format!("live (ttl {})", ttl.ttl_ledgers().unwrap_or(0)),
        ),
        rentkeeper_core::EntryState::ExpiredButPresent(_) => {
            ("expired".to_string(), "needs restore".to_string())
        }
        rentkeeper_core::EntryState::Archived(_) => {
            ("archived".to_string(), "needs restore".to_string())
        }
    };
    println!("{kind:<12} {durability:<11} {live_until:>18} {status:>12}");
}

fn durability_of(key: &LedgerKey) -> Option<Durability> {
    match key {
        LedgerKey::ContractData(data) => Some(Durability::from_xdr(data.durability)),
        _ => None,
    }
}

/// The reserved `ScVal` key for contract instance entries.
#[must_use]
pub fn instance_key() -> ScVal {
    ScVal::LedgerKeyContractInstance
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_key_is_reserved_symbol() {
        assert_eq!(instance_key(), ScVal::LedgerKeyContractInstance);
    }

    #[test]
    fn durability_of_reads_contract_data_keys() {
        let mut cid = [0u8; 32];
        cid[5] = 9;
        let key =
            LedgerKeys::contract_data(&cid, &ScVal::U32(1), ContractDataDurability::Persistent);
        assert_eq!(durability_of(&key), Some(Durability::Persistent));

        let code_key = LedgerKeys::contract_code(&cid);
        assert_eq!(durability_of(&code_key), None);
    }
}
