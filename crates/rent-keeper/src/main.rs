#![allow(dead_code)]
//! `rent-keeper`: off-chain daemon that watches Soroban ledger-entry TTLs and
//! submits batched `ExtendFootprintTtl` operations before eviction.

mod config;
mod metrics;
mod metrics_server;

fn main() {}
