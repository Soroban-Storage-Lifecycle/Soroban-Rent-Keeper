//! Integration tests against the public Stellar testnet. Read-only: they
//! observe state, never submit transactions or spend funds.
//!
//! Run with: `cargo test -p rentkeeper-core --test integration --features
//! integration-tests -- --ignored`. They are `#[ignore]`d by default so
//! `cargo test` stays hermetic.

#![cfg(feature = "integration-tests")]

use rentkeeper_core::{LedgerKeys, SorobanProvider};
use stellar_xdr::{ContractDataDurability, ScVal};

const TESTNET_RPC: &str = "https://soroban-testnet.stellar.org:443";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// The native XLM Stellar Asset Contract on testnet. Its instance entry is
/// kept alive by the network itself, so it is always observable.
const XLM_CONTRACT: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

fn testnet_provider() -> SorobanProvider {
    SorobanProvider::connect(TESTNET_RPC).expect("connect testnet")
}

fn xlm_contract_bytes() -> [u8; 32] {
    let strkey = stellar_strkey::Strkey::from_string(XLM_CONTRACT).expect("valid strkey");
    match strkey {
        stellar_strkey::Strkey::Contract(stellar_strkey::Contract(bytes)) => bytes,
        _ => panic!("not a contract strkey"),
    }
}

#[tokio::test]
#[ignore = "requires testnet connectivity; run with --ignored"]
async fn network_passphrase_matches_testnet() {
    let provider = testnet_provider();
    let passphrase = provider.network_passphrase().await.expect("passphrase");
    assert_eq!(passphrase, TESTNET_PASSPHRASE);
}

#[tokio::test]
#[ignore = "requires testnet connectivity; run with --ignored"]
async fn ttl_constants_match_network_settings() {
    let provider = testnet_provider();
    let constants = provider.ttl_constants().await.expect("constants");
    // Testnet protocol 22+ settings: max_entry_ttl well above a year of 5s
    // ledgers would be unusual, so assert sane lower bounds only.
    assert!(
        constants.max_entry_ttl >= 1_000_000,
        "unexpected max_entry_ttl: {}",
        constants.max_entry_ttl
    );
    assert!(constants.min_persistent_ttl >= 1_000);
    assert!(constants.min_temporary_ttl >= 1);
    assert!(constants.seconds_per_ledger > 0);
}

#[tokio::test]
#[ignore = "requires testnet connectivity; run with --ignored"]
async fn observe_classifies_live_xlm_contract_instance() {
    let provider = testnet_provider();
    let id = xlm_contract_bytes();
    let key = LedgerKeys::contract_data(
        &id,
        &ScVal::LedgerKeyContractInstance,
        ContractDataDurability::Persistent,
    );
    let observations = provider
        .observe_entries(&[key])
        .await
        .expect("observations");
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert!(
        matches!(observation.entry, rentkeeper_core::EntryState::Live(_)),
        "native XLM instance must be live, got {:?}",
        observation.entry
    );
    assert!(!observation.needs_restore());
    if let rentkeeper_core::EntryState::Live(ttl) = &observation.entry {
        assert!(ttl.ttl_ledgers().unwrap_or(0) > 0);
    }
}

#[tokio::test]
#[ignore = "requires testnet connectivity; run with --ignored"]
async fn observe_reports_archived_for_bogus_contract() {
    let provider = testnet_provider();
    // An address that is not a deployed contract: its instance entry is absent.
    let mut id = [0u8; 32];
    id[0] = 0xFF;
    let key = LedgerKeys::contract_data(
        &id,
        &ScVal::LedgerKeyContractInstance,
        ContractDataDurability::Persistent,
    );
    let observations = provider
        .observe_entries(std::slice::from_ref(&key))
        .await
        .expect("observations");
    assert_eq!(observations.len(), 1);
    assert!(observations[0].needs_restore());
    assert!(matches!(
        observations[0].entry,
        rentkeeper_core::EntryState::Archived(_)
    ));
}

#[tokio::test]
#[ignore = "requires testnet connectivity; run with --ignored"]
async fn observation_order_matches_input_keys() {
    let provider = testnet_provider();
    let id = xlm_contract_bytes();
    let live_key = LedgerKeys::contract_data(
        &id,
        &ScVal::LedgerKeyContractInstance,
        ContractDataDurability::Persistent,
    );
    let mut bogus = [0u8; 32];
    bogus[0] = 0xFF;
    let dead_key = LedgerKeys::contract_data(
        &bogus,
        &ScVal::LedgerKeyContractInstance,
        ContractDataDurability::Persistent,
    );
    let observations = provider
        .observe_entries(&[live_key, dead_key])
        .await
        .expect("observations");
    assert_eq!(observations.len(), 2);
    assert!(matches!(
        observations[0].entry,
        rentkeeper_core::EntryState::Live(_)
    ));
    assert!(matches!(
        observations[1].entry,
        rentkeeper_core::EntryState::Archived(_)
    ));
}
