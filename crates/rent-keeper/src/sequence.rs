//! Fee-payer sequence tracking that tolerates concurrent submitters.
//!
//! The daemon keeps the last known sequence in memory and increments it
//! locally between submissions. On a `tx_bad_seq` rejection it refreshes once
//! from the node and retries, so a foreign submission from the same account
//! does not stall protection for a whole poll interval.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::watcher::KeeperError;
use rentkeeper_core::SorobanProvider;

/// Tracks the fee payer's next sequence number.
#[derive(Debug, Clone)]
pub struct SequenceTracker {
    provider: SorobanProvider,
    account_id: String,
    state: Arc<Mutex<Option<i64>>>,
}

impl SequenceTracker {
    /// Creates a tracker for the given fee payer account (`G...` strkey).
    #[must_use]
    pub fn new(provider: SorobanProvider, account_id: String) -> Self {
        Self {
            provider,
            account_id,
            state: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the next sequence number to use, refreshing from the node only
    /// when the local cache is empty.
    ///
    /// # Errors
    /// Errors when the account cannot be fetched (e.g. unfunded fee payer).
    pub async fn next_sequence(&self) -> Result<i64, KeeperError> {
        let mut cached = self.state.lock().await;
        match *cached {
            Some(seq) => {
                *cached = Some(seq + 1);
                Ok(seq + 1)
            }
            None => {
                let entry = self
                    .provider
                    .get_account(&self.account_id)
                    .await
                    .map_err(|e| {
                        KeeperError::Rpc(format!("get_account for fee payer (is it funded?): {e}"))
                    })?;
                let next = entry.seq_num.0 + 1;
                *cached = Some(next);
                Ok(next)
            }
        }
    }

    /// Reports a submission failure: if it looks like a sequence error, the
    /// local cache is dropped so the next `next_sequence` re-syncs with the
    /// node. Returns true when the cache was invalidated.
    pub async fn report_failure(&self, error: &KeeperError) -> bool {
        if is_bad_seq_error(error) {
            *self.state.lock().await = None;
            return true;
        }
        false
    }
}

/// Heuristically detects sequence-related submission failures.
#[must_use]
pub fn is_bad_seq_error(error: &KeeperError) -> bool {
    let text = error.to_string();
    text.contains("tx_bad_seq")
        || text.contains("bad_seq")
        || text.contains("BadSequence")
        || text.contains("BAD_SEQ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_seq_detection_covers_variants() {
        assert!(is_bad_seq_error(&KeeperError::Rpc(
            "send_transaction: tx_bad_seq".into()
        )));
        assert!(is_bad_seq_error(&KeeperError::Rpc(
            "node said BadSequence number".into()
        )));
        assert!(!is_bad_seq_error(&KeeperError::Rpc("timeout".into())));
        assert!(!is_bad_seq_error(&KeeperError::Transaction(
            "empty plan".into()
        )));
    }

    #[tokio::test]
    async fn cached_sequence_increments_without_rpc() {
        // Tracker with an unreachable provider address: proves the cache path
        // never touches the network after priming.
        let provider = SorobanProvider::connect("http://127.0.0.1:1").expect("client builds");
        let tracker = SequenceTracker::new(
            provider,
            "GA7QYNF7SowQc3RwGxDq2jTnKlViNgmLncATJznaXStreaming".to_string(),
        );
        {
            let mut cached = tracker.state.lock().await;
            *cached = Some(100);
        }
        assert_eq!(tracker.next_sequence().await.expect("seq"), 101);
        assert_eq!(tracker.next_sequence().await.expect("seq"), 102);
        // Failure reporting drops the cache.
        assert!(
            tracker
                .report_failure(&KeeperError::Rpc("tx_bad_seq".into()))
                .await
        );
        // Next call would re-fetch (and fail against the dead endpoint).
        assert!(tracker.next_sequence().await.is_err());
    }
}
