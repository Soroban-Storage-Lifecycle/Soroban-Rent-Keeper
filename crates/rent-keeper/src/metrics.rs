//! Prometheus metrics for the rent keeper daemon.

use std::sync::Arc;

use prometheus::{Encoder as _, IntCounter, IntGauge, Registry, TextEncoder};

/// Metrics registry plus the counters the daemon updates.
#[derive(Debug, Clone)]
pub struct Metrics {
    registry: Registry,
    /// Runs of the poll loop that completed without a fatal error.
    pub poll_cycles: IntCounter,
    /// Entries found at or below the alert horizon in the last cycle.
    pub entries_at_risk: IntGauge,
    /// Extend transactions that were signed and submitted.
    pub extends_submitted: IntCounter,
    /// Submissions the node accepted (PENDING or duplicate).
    pub extends_accepted: IntCounter,
    /// Submissions the node rejected.
    pub extends_rejected: IntCounter,
    /// Ledger height of the last successful observation snapshot.
    pub latest_observed_ledger: IntGauge,
}

impl Metrics {
    /// Creates the metric set registered in a fresh registry.
    ///
    /// # Errors
    /// Errors when Prometheus registration fails (duplicate names), which
    /// indicates a programming error rather than a runtime condition.
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let poll_cycles = IntCounter::new(
            "rentkeeper_poll_cycles_total",
            "Poll cycles completed by the daemon",
        )?;
        let entries_at_risk = IntGauge::new(
            "rentkeeper_entries_at_risk",
            "Entries at or below the alert horizon in the last cycle",
        )?;
        let extends_submitted = IntCounter::new(
            "rentkeeper_extends_submitted_total",
            "Extend transactions signed and submitted",
        )?;
        let extends_accepted = IntCounter::new(
            "rentkeeper_extends_accepted_total",
            "Extend transactions accepted by the node",
        )?;
        let extends_rejected = IntCounter::new(
            "rentkeeper_extends_rejected_total",
            "Extend transactions rejected by the node",
        )?;
        let latest_observed_ledger = IntGauge::new(
            "rentkeeper_latest_observed_ledger",
            "Ledger height of the last observation snapshot",
        )?;

        registry.register(Box::new(poll_cycles.clone()))?;
        registry.register(Box::new(entries_at_risk.clone()))?;
        registry.register(Box::new(extends_submitted.clone()))?;
        registry.register(Box::new(extends_accepted.clone()))?;
        registry.register(Box::new(extends_rejected.clone()))?;
        registry.register(Box::new(latest_observed_ledger.clone()))?;

        Ok(Self {
            registry,
            poll_cycles,
            entries_at_risk,
            extends_submitted,
            extends_accepted,
            extends_rejected,
            latest_observed_ledger,
        })
    }

    /// Renders the registry in Prometheus text exposition format.
    ///
    /// # Errors
    /// Errors when encoding fails, which should never happen for these types.
    pub fn gather(&self) -> Result<Vec<u8>, prometheus::Error> {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buffer)?;
        Ok(buffer)
    }
}

/// Shared handle used by the loop and the metrics server.
pub type SharedMetrics = Arc<Metrics>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_in_prometheus_format() {
        let metrics = Metrics::new().expect("registry");
        metrics.poll_cycles.inc_by(3);
        metrics.entries_at_risk.set(7);
        let body = String::from_utf8(metrics.gather().expect("gather")).expect("utf8");
        assert!(body.contains("rentkeeper_poll_cycles_total 3"));
        assert!(body.contains("rentkeeper_entries_at_risk 7"));
    }

    #[test]
    fn counters_update_independently() {
        let metrics = Metrics::new().expect("registry");
        metrics.extends_submitted.inc();
        metrics.extends_accepted.inc();
        metrics.extends_rejected.inc_by(2);
        let body = String::from_utf8(metrics.gather().expect("gather")).expect("utf8");
        assert!(body.contains("rentkeeper_extends_submitted_total 1"));
        assert!(body.contains("rentkeeper_extends_accepted_total 1"));
        assert!(body.contains("rentkeeper_extends_rejected_total 2"));
    }
}
