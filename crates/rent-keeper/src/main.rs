//! `rent-keeper`: off-chain daemon that watches Soroban ledger-entry TTLs and
//! submits batched `ExtendFootprintTtl` operations before eviction.

mod config;
mod metrics;
mod metrics_server;
mod secret;
mod sequence;
mod watcher;

use std::path::PathBuf;

use clap::Parser as _;
use rentkeeper_core::tx::FeePayer;
use rentkeeper_core::SorobanProvider;

use sequence::SequenceTracker;

/// Long-running keeper options.
#[derive(Debug, clap::Parser)]
#[command(
    name = "rent-keeper",
    about = "Watch Soroban entry TTLs and keep them alive",
    version
)]
pub struct Args {
    /// Path to the TOML configuration file.
    #[arg(long, short, env = "RENT_KEEPER_CONFIG")]
    pub config: PathBuf,

    /// Validate the configuration and exit without running.
    #[arg(long)]
    pub check: bool,

    /// Log filter (tracing `RUST_LOG` syntax); config file can also set this.
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_filter: String,
}

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
    let args = Args::parse();
    init_tracing(&args.log_filter);

    let valid = match config::load_config(&args.config) {
        Ok(valid) => valid,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(2);
        }
    };

    if args.check {
        println!(
            "configuration OK: {} watch rule(s), risk window {} ledgers, poll every {:?}",
            valid.watch.len(),
            valid.risk_window.alert_horizon_ledgers,
            valid.poll_interval
        );
        return;
    }

    let payer = match FeePayer::from_secret_key_str(valid.secret_key.expose_secret()) {
        Ok(payer) => payer,
        Err(err) => {
            eprintln!("fee payer error: {err}");
            std::process::exit(2);
        }
    };

    let provider = match SorobanProvider::connect(&valid.rpc_url) {
        Ok(provider) => provider,
        Err(err) => {
            eprintln!("rpc error: {err}");
            std::process::exit(2);
        }
    };

    // Best effort: refresh TTL constants from the network itself.
    let mut valid = valid;
    match provider.ttl_constants().await {
        Ok(network_constants) => {
            tracing::info!(
                max_entry_ttl = network_constants.max_entry_ttl,
                "using network state-archival settings"
            );
            valid.constants = network_constants;
        }
        Err(err) => {
            tracing::warn!(error = %err, "could not fetch network TTL settings; using defaults");
        }
    }

    let shared_metrics = match metrics::Metrics::new() {
        Ok(m) => std::sync::Arc::new(m),
        Err(err) => {
            eprintln!("metrics error: {err}");
            std::process::exit(2);
        }
    };

    if let Some(port) = valid.metrics_port {
        let metrics = std::sync::Arc::clone(&shared_metrics);
        tokio::spawn(async move {
            if let Err(err) = metrics_server::serve_metrics(port, metrics).await {
                tracing::error!(error = %err, "metrics server stopped");
            }
        });
    }

    let sequence = SequenceTracker::new(provider.clone(), payer.account_id_strkey());
    run_loop(&provider, &valid, &payer, &shared_metrics, &sequence).await;
}

/// Bounds for transient-failure retries within one cycle.
const RETRY_ATTEMPTS: usize = 3;
const RETRY_BASE_DELAY_MS: u64 = 1_000;

async fn run_loop(
    provider: &SorobanProvider,
    config: &config::ValidConfig,
    payer: &FeePayer,
    shared_metrics: &metrics::SharedMetrics,
    sequence: &SequenceTracker,
) {
    let mut ticker = tokio::time::interval(config.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(sig) => sig,
        Err(err) => {
            tracing::error!(error = %err, "cannot install SIGTERM handler");
            return;
        }
    };
    let mut sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    {
        Ok(sig) => sig,
        Err(err) => {
            tracing::error!(error = %err, "cannot install SIGINT handler");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received; shutting down");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received; shutting down");
                break;
            }
        }

        // Bounded retries for transient RPC failures within the cycle.
        let mut attempt = 0usize;
        loop {
            match watcher::run_cycle(provider, config, payer, sequence).await {
                Ok(report) => {
                    shared_metrics.poll_cycles.inc();
                    shared_metrics
                        .latest_observed_ledger
                        .set(i64::from(report.observed_ledger));
                    shared_metrics
                        .entries_at_risk
                        .set(i64::try_from(report.entries_at_risk).unwrap_or(i64::MAX));
                    shared_metrics
                        .extends_submitted
                        .inc_by(u64::try_from(report.transactions).unwrap_or(u64::MAX));
                    if report.extend_submitted {
                        shared_metrics.extends_accepted.inc();
                    }
                    tracing::info!(
                        ledger = report.observed_ledger,
                        at_risk = report.entries_at_risk,
                        submitted = report.transactions,
                        "cycle complete"
                    );
                    break;
                }
                Err(err) => {
                    attempt += 1;
                    if attempt >= RETRY_ATTEMPTS || !is_transient(&err) {
                        tracing::error!(error = %err, attempts = attempt, "cycle failed");
                        if matches!(err, watcher::KeeperError::Rpc(_)) {
                            shared_metrics.extends_rejected.inc();
                        }
                        break;
                    }
                    let delay = RETRY_BASE_DELAY_MS * (1 << (attempt - 1));
                    tracing::warn!(
                        error = %err,
                        attempt,
                        delay_ms = delay,
                        "transient failure; retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }
    tracing::info!("rent-keeper stopped");
}

/// Only transport-level RPC failures are retried; validation and transaction
/// errors are deterministic and re-planning will not fix them.
fn is_transient(err: &watcher::KeeperError) -> bool {
    matches!(err, watcher::KeeperError::Rpc(_))
}
