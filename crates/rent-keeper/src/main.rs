//! `rent-keeper`: off-chain daemon that watches Soroban ledger-entry TTLs and
//! submits batched `ExtendFootprintTtl` operations before eviction.

mod config;
mod metrics;
mod metrics_server;
mod secret;
mod watcher;

use std::path::PathBuf;

use clap::Parser as _;
use rentkeeper_core::tx::FeePayer;
use rentkeeper_core::SorobanProvider;

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

    run_loop(&provider, &valid, &payer, &shared_metrics).await;
}

async fn run_loop(
    provider: &SorobanProvider,
    config: &config::ValidConfig,
    payer: &FeePayer,
    shared_metrics: &metrics::SharedMetrics,
) {
    let mut ticker = tokio::time::interval(config.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match watcher::run_cycle(provider, config, payer).await {
            Ok(report) => {
                shared_metrics.poll_cycles.inc();
                shared_metrics
                    .latest_observed_ledger
                    .set(i64::from(report.observed_ledger));
                shared_metrics
                    .entries_at_risk
                    .set(i64::try_from(report.entries_at_risk).unwrap_or(i64::MAX));
                if report.extend_submitted {
                    shared_metrics.extends_submitted.inc();
                    shared_metrics.extends_accepted.inc();
                }
                tracing::info!(
                    ledger = report.observed_ledger,
                    at_risk = report.entries_at_risk,
                    submitted = report.extend_submitted,
                    "cycle complete"
                );
            }
            Err(err) => {
                tracing::error!(error = %err, "poll cycle failed");
                if matches!(err, watcher::KeeperError::Rpc(_)) {
                    shared_metrics.extends_rejected.inc();
                }
            }
        }
    }
}
