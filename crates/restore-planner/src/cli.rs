//! CLI plumbing shared by the `restore-planner` subcommands.

use std::path::PathBuf;

use rentkeeper_core::plan::{plan_from_json, plan_to_json, ArchivalPlan};
use rentkeeper_core::ttl::TtlConstants;
use rentkeeper_core::SorobanProvider;
use stellar_xdr::{ReadXdr as _, ScVal};

/// Shared connection options for every subcommand.
#[derive(Debug, clap::Args)]
pub struct ConnectOpts {
    /// Soroban RPC endpoint URL.
    #[arg(
        long,
        short,
        env = "SOROBAN_RPC_URL",
        default_value = "https://soroban-testnet.stellar.org:443"
    )]
    pub rpc_url: String,

    /// Network passphrase.
    #[arg(
        long,
        env = "SOROBAN_NETWORK_PASSPHRASE",
        default_value = "Test SDF Network ; September 2015"
    )]
    pub network_passphrase: String,
}

/// Top-level command line.
#[derive(Debug, clap::Parser)]
#[command(
    name = "restore-planner",
    about = "Inspect archived Soroban entries and build restore/extend plans",
    version
)]
pub struct Cli {
    #[command(flatten)]
    pub connect: ConnectOpts,

    /// Log filter (`RUST_LOG` syntax).
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_filter: String,

    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Inspect ledger entries: show durability, TTL, and archival status.
    Inspect {
        /// `C...` contract strkey whose entries should be inspected.
        #[arg(long, short = 'c')]
        contract: String,

        /// Optional base64 `ScVal` key XDR to inspect a single data entry.
        #[arg(long)]
        key_xdr: Option<String>,

        /// Durability for --key-xdr (persistent or temporary).
        #[arg(long, default_value = "persistent")]
        durability: String,

        /// Also inspect the contract's Wasm code entry.
        #[arg(long, requires = "wasm_hash")]
        include_code: bool,

        /// Hex Wasm hash to inspect (implies code entry inspection).
        #[arg(long)]
        wasm_hash: Option<String>,
    },

    /// Build a restore plan for archived entries and write it as JSON.
    PlanRestore {
        /// `C...` contract strkey.
        #[arg(long, short = 'c')]
        contract: String,

        /// Base64 `ScVal` key XDRs of archived entries (repeatable).
        #[arg(long = "key-xdr", required = true)]
        key_xdrs: Vec<String>,

        /// Durability of the listed keys (all entries share it).
        #[arg(long, default_value = "persistent")]
        durability: String,

        /// Target TTL in days after restore (clamped to network max).
        #[arg(long, default_value_t = 30.0)]
        ttl_days: f64,

        /// Output path for the JSON plan (defaults to stdout).
        #[arg(long, short)]
        out: Option<PathBuf>,
    },

    /// Build an extend plan for live entries and write it as JSON.
    PlanExtend {
        /// `C...` contract strkey.
        #[arg(long, short = 'c')]
        contract: String,

        /// Base64 `ScVal` key XDRs of entries to extend (repeatable).
        #[arg(long = "key-xdr", required = true)]
        key_xdrs: Vec<String>,

        /// Durability of the listed keys.
        #[arg(long, default_value = "persistent")]
        durability: String,

        /// Target TTL in days (clamped to network max).
        #[arg(long, default_value_t = 30.0)]
        ttl_days: f64,

        /// Output path for the JSON plan (defaults to stdout).
        #[arg(long, short)]
        out: Option<PathBuf>,
    },

    /// Print a summary of a previously generated plan JSON file.
    ShowPlan {
        /// Path to the plan JSON file (or '-' for stdin).
        #[arg(long, short)]
        plan: String,
    },
}

/// Errors from CLI helpers.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Invalid user input.
    #[error("{0}")]
    Invalid(String),
    /// RPC or plan generation failure.
    #[error("{0}")]
    Operation(String),
    /// File I/O failure.
    #[error("io: {0}")]
    Io(String),
}

/// Parses a `C...` strkey into raw contract id bytes.
pub fn contract_id_bytes(contract: &str) -> Result<[u8; 32], CliError> {
    let strkey = stellar_strkey::Strkey::from_string(contract)
        .map_err(|e| CliError::Invalid(format!("contract strkey: {e}")))?;
    match strkey {
        stellar_strkey::Strkey::Contract(stellar_strkey::Contract(bytes)) => Ok(bytes),
        _ => Err(CliError::Invalid(format!(
            "{contract} is not a C... contract strkey"
        ))),
    }
}

/// Parses hex (with optional 0x) into 32 bytes.
pub fn wasm_hash_bytes(hash: &str) -> Result<[u8; 32], CliError> {
    let stripped = hash.strip_prefix("0x").unwrap_or(hash);
    if stripped.len() != 64 {
        return Err(CliError::Invalid(
            "wasm hash must be 32 bytes of hex".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in stripped.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0]).ok_or_else(|| CliError::Invalid("bad hex".into()))?;
        let lo = hex_val(
            *chunk
                .get(1)
                .ok_or_else(|| CliError::Invalid("bad hex".into()))?,
        )
        .ok_or_else(|| CliError::Invalid("bad hex".into()))?;
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

/// Parses base64 `ScVal` XDR from the command line.
pub fn parse_scval(key_xdr: &str) -> Result<ScVal, CliError> {
    ScVal::from_xdr_base64(key_xdr.as_bytes(), stellar_xdr::Limits::none())
        .map_err(|e| CliError::Invalid(format!("key-xdr: {e}")))
}

/// Maps a durability name to its XDR variant.
pub fn parse_durability(name: &str) -> Result<stellar_xdr::ContractDataDurability, CliError> {
    match name {
        "persistent" => Ok(stellar_xdr::ContractDataDurability::Persistent),
        "temporary" => Ok(stellar_xdr::ContractDataDurability::Temporary),
        other => Err(CliError::Invalid(format!(
            "unknown durability '{other}' (expected persistent|temporary)"
        ))),
    }
}

/// Connects to the RPC endpoint named on the command line.
pub fn connect(opts: &ConnectOpts) -> Result<SorobanProvider, CliError> {
    SorobanProvider::connect(&opts.rpc_url).map_err(|e| CliError::Operation(e.to_string()))
}

/// TTL constants for the network (uses public defaults in the CLI).
#[must_use]
pub fn constants() -> TtlConstants {
    TtlConstants::stellar_public()
}

/// Converts days into a clamped ledger count.
#[must_use]
pub fn days_to_extend_to(days: f64) -> u32 {
    rentkeeper_core::RiskWindow::from_days(days).extend_to_ledgers(&constants())
}

/// Writes a plan as JSON to stdout or a file.
///
/// # Errors
/// Errors on serialization or file write failures.
pub fn emit_plan(plan: &ArchivalPlan, out: Option<&PathBuf>) -> Result<(), CliError> {
    let json = plan_to_json(plan).map_err(|e| CliError::Operation(e.to_string()))?;
    match out {
        Some(path) => std::fs::write(path, json + "\n")
            .map_err(|e| CliError::Io(format!("write {}: {e}", path.display()))),
        None => {
            println!("{json}");
            Ok(())
        }
    }
}

/// Reads a plan from a file path or stdin (`-`).
///
/// # Errors
/// Errors on read or parse failures.
pub fn read_plan(path: &str) -> Result<ArchivalPlan, CliError> {
    let json = if path == "-" {
        use std::io::Read as _;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| CliError::Io(format!("stdin: {e}")))?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| CliError::Io(format!("read {path}: {e}")))?
    };
    plan_from_json(&json).map_err(|e| CliError::Invalid(format!("plan json: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_strkeys_parse() {
        let id = contract_id_bytes("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4")
            .expect("valid");
        assert_eq!(id.len(), 32);
        assert!(
            contract_id_bytes("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWF5").is_err()
        );
        assert!(contract_id_bytes("nonsense").is_err());
    }

    #[test]
    fn wasm_hashes_parse_with_and_without_prefix() {
        let hex = "aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd";
        let with = wasm_hash_bytes(&format!("0x{hex}")).expect("prefixed");
        let without = wasm_hash_bytes(hex).expect("bare");
        assert_eq!(with, without);
        assert_eq!(with[0], 0xaa);
        assert_eq!(with[31], 0xdd);
        assert!(wasm_hash_bytes("abcd").is_err());
    }

    #[test]
    fn durability_names_map() {
        assert!(parse_durability("persistent").is_ok());
        assert!(parse_durability("temporary").is_ok());
        assert!(parse_durability("eternal").is_err());
    }

    #[test]
    fn days_convert_to_clamped_ledgers() {
        assert_eq!(days_to_extend_to(30.0), 518_400);
        assert_eq!(days_to_extend_to(10_000.0), constants().max_entry_ttl);
    }

    #[test]
    fn scval_parsing_accepts_u32() {
        let val = parse_scval("AAAAAwAAAAc=").expect("u32 xdr");
        assert_eq!(val, stellar_xdr::ScVal::U32(7));
        assert!(parse_scval("!!!").is_err());
    }

    #[test]
    fn plans_roundtrip_through_emit_and_read() {
        let plan = ArchivalPlan {
            network_passphrase: "Test".to_string(),
            reference_ledger: 5,
            extend_to: 100,
            entries: vec![],
        };
        let dir = std::env::temp_dir().join(format!("restore-planner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("plan.json");
        emit_plan(&plan, Some(&path)).expect("emit");
        let back = read_plan(path.to_string_lossy().as_ref()).expect("read");
        assert_eq!(back, plan);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
