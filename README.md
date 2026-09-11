# Soroban-Rent-Keeper

Off-chain tooling that keeps Soroban contract state alive on Stellar.

Soroban ledger entries expire: every entry has a `liveUntilLedgerSeq`, and once
that passes, persistent entries are archived and must be restored (at a cost)
before they can be used again. This workspace contains two cooperating tools:

- **`rent-keeper`** — a long-running daemon that watches the TTLs of the
  entries you care about and submits batched `ExtendFootprintTtl`
  transactions before anything expires.
- **`restore-planner`** — a CLI for inspecting entries (live / expired /
  archived) and generating restore and extend plans as JSON.

Both binaries share `rentkeeper-core`, which holds the TTL model, the
plan data structures, RPC observation, and the transaction builder/signer.

## Workspace layout

| Crate | Purpose |
| --- | --- |
| `crates/rentkeeper-core` | Ledger keys, TTL math, risk windows, plans, RPC provider, tx building/signing |
| `crates/rent-keeper` | The daemon: config, poll loop, extend submission, Prometheus metrics |
| `crates/restore-planner` | The operator CLI: inspect, plan-restore, plan-extend, show-plan |

## Building

```bash
cargo build --release
# binaries in target/release/{rent-keeper,restore-planner}
```

## rent-keeper

### Configuration

Create `rent-keeper.toml` (kept out of git by `.gitignore`; never commit the
secret key):

```toml
rpc_url = "https://soroban-testnet.stellar.org:443"
network_passphrase = "Test SDF Network ; September 2015"
secret_key = "SB..."                    # fee payer; fund this account
poll_interval_secs = 30                 # optional, default 30
risk_window_days = 7.0                  # optional, default 7
metrics_port = 9100                     # optional; omit to disable

# Watch rules: explicit entries to keep alive.
[[watch]]
type = "instance"
contract_id = "C..."                    # contract instance entry

[[watch]]
type = "data_key"
contract_id = "C..."
key_xdr = "AAAAAwAAAAc="                # base64 ScVal XDR
durability = "persistent"               # or "temporary"

[[watch]]
type = "contract_code"
wasm_hash = "aabb..."                   # 32-byte hex Wasm hash
```

Validate without running:

```bash
rent-keeper --config rent-keeper.toml --check
```

Run:

```bash
rent-keeper --config rent-keeper.toml
```

Each cycle the daemon fetches the watched entries plus their TTL companions
from `getLedgerEntries`, builds an `ExtendFootprintTtl` transaction for every
entry at or below the risk window, signs it with the fee payer key, and
submits it. Entries that have already expired are logged (with a warning) but
not touched — restoring is an operator decision because of the fee; use
`restore-planner` for that. Metrics are served on `metrics_port` at
`/metrics` when configured.

> TTL constants (`max_entry_ttl`, minimum TTLs) are read from the network's
> `StateArchival` config entry at startup, falling back to public-network
> defaults if unavailable.

## restore-planner

Inspect entries on chain:

```bash
restore-planner inspect --contract C... --key-xdr "AAAAAwAAAAc=" --durability persistent
restore-planner inspect --contract C... --wasm-hash aabb...
```

Generate a restore plan for archived entries (validates that the entries
really are archived before writing the plan):

```bash
restore-planner plan-restore --contract C... \
  --key-xdr "AAAAAwAAAAc=" --durability persistent \
  --ttl-days 30 --out restore-plan.json
```

Generate an extend plan for live entries:

```bash
restore-planner plan-extend --contract C... \
  --key-xdr "AAAAAwAAAAc=" --durability persistent \
  --ttl-days 30 --out extend-plan.json
```

Review a plan file (or `-` for stdin):

```bash
restore-planner show-plan --plan restore-plan.json
```

Plans are JSON documents containing base64 ledger-key XDRs, the operation
kind, the observed TTL, and the target TTL, so they can be checked into an
ops workflow, diffed, and later fed to a signing/submission step.

## How TTL extension works here

The daemon uses the protocol semantics for `ExtendFootprintTtl`:
`extend_to` is an absolute remaining-TTL target measured from the current
ledger (not an increment), persistent entries are clamped by the network's
`max_entry_ttl`, and the footprint travels in the transaction's
`SorobanTransactionData` extension. Plans therefore store the clamped
`extend_to` value rather than a raw day count.

## Development

```bash
cargo test --workspace            # unit tests (63)
cargo clippy --workspace --all-targets   # zero warnings expected
cargo fmt --all -- --check
```

The core crate is fully offline-testable: planning, TTL math, key hashing,
plan (de)serialization, and signing are all covered without network access.

## Safety notes

- The fee payer secret key must never be committed; `.gitignore` excludes
  `rent-keeper.toml`, `.env*`, and local overrides.
- Restores cost real XLM proportional to entry size; review plans before
  signing them.
- Extension target is clamped to the network `max_entry_ttl`; a plan's
  `extend_to` is always a valid target for persistent entries.
