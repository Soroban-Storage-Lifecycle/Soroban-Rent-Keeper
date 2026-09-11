//! Transaction building and Ed25519 signing for extend/restore operations.
//!
//! The builder produces classic `TransactionEnvelope::Tx` (v1) envelopes whose
//! single operation is `ExtendFootprintTtl` or `RestoreFootprint` with the
//! plan's footprint. Soroban resource data is not required for these
//! host-function-free archival ops; nodes bill them as classic ops.

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::Digest;
use stellar_xdr::{
    DecoratedSignature, ExtendFootprintTtlOp, ExtensionPoint, LedgerFootprint, Limits, Memo,
    MuxedAccount, Operation, OperationBody, Preconditions, PublicKey, RestoreFootprintOp,
    SequenceNumber, Signature, SignatureHint, SorobanResources, SorobanTransactionData,
    SorobanTransactionDataExt, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

use crate::error::RentkeeperError;
use crate::plan::{ArchivalPlan, OperationKind};

/// Builds and signs archival transactions for a single fee payer.
#[derive(Debug, Clone)]
pub struct TxBuilder {
    network_passphrase: String,
    /// Base fee per operation in stroops. The node enforces the real minimum.
    base_fee: u64,
}

/// Default base fee used when none is configured: 100 stroops (classic min).
pub const DEFAULT_BASE_FEE: u64 = 100;

impl TxBuilder {
    /// Creates a builder for the given network.
    #[must_use]
    pub fn new(network_passphrase: &str) -> Self {
        Self {
            network_passphrase: network_passphrase.to_string(),
            base_fee: DEFAULT_BASE_FEE,
        }
    }

    /// Overrides the base fee (stroops per operation).
    #[must_use]
    pub fn with_base_fee(mut self, base_fee: u64) -> Self {
        self.base_fee = base_fee;
        self
    }

    /// The network passphrase transactions are built for.
    #[must_use]
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// Builds an unsigned envelope for the plan's single archival operation.
    ///
    /// # Errors
    /// Errors when the plan is empty, has too many entries for one footprint,
    /// or XDR encoding fails while computing the signing hash.
    pub fn build_unsigned(
        &self,
        plan: &ArchivalPlan,
        source: &PublicKey,
        seq_num: i64,
    ) -> Result<TransactionEnvelope, RentkeeperError> {
        if plan.is_empty() {
            return Err(RentkeeperError::Transaction(
                "refusing to build a transaction for an empty plan".to_string(),
            ));
        }
        // LedgerFootprint caps each side at 100 keys.
        if plan.len() > 100 {
            return Err(RentkeeperError::Transaction(format!(
                "plan has {} entries; footprint supports at most 100",
                plan.len()
            )));
        }

        // ExtendFootprintTtl and RestoreFootprint read their target keys from
        // the Soroban transaction data extension, not from a host-function arg.
        let keys = plan.footprint();
        let read_write =
            VecM::try_from(keys).map_err(|e| RentkeeperError::Xdr(format!("footprint: {e}")))?;
        let footprint = LedgerFootprint {
            read_only: VecM::default(),
            read_write,
        };

        let body = match plan.entries.first().map(|e| e.kind) {
            Some(OperationKind::Extend) => {
                OperationBody::ExtendFootprintTtl(ExtendFootprintTtlOp {
                    ext: ExtensionPoint::V0,
                    extend_to: plan.extend_to,
                })
            }
            Some(OperationKind::Restore) => OperationBody::RestoreFootprint(RestoreFootprintOp {
                ext: ExtensionPoint::V0,
            }),
            None => {
                return Err(RentkeeperError::Transaction(
                    "plan entries disappeared during build".to_string(),
                ))
            }
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(pubkey_bytes(source)?)),
            fee: u32::try_from(self.base_fee).unwrap_or(u32::MAX),
            seq_num: SequenceNumber(seq_num),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::try_from(vec![Operation {
                source_account: None,
                body,
            }])
            .map_err(|e| RentkeeperError::Xdr(format!("operations: {e}")))?,
            // Zero resource estimates; nodes clamp up to the real cost. The
            // footprint itself is what makes the archival op meaningful.
            ext: TransactionExt::V1(SorobanTransactionData {
                ext: SorobanTransactionDataExt::V0,
                resources: SorobanResources {
                    footprint,
                    instructions: 0,
                    disk_read_bytes: 0,
                    write_bytes: 0,
                },
                resource_fee: 0,
            }),
        };

        Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: stellar_xdr::VecM::default(),
        }))
    }

    /// Signs an envelope with the given secret key, appending one decorated
    /// signature for the fee payer.
    ///
    /// # Errors
    /// Errors when the signing hash cannot be computed.
    pub fn sign(
        &self,
        envelope: &mut TransactionEnvelope,
        signing_key: &SigningKey,
    ) -> Result<(), RentkeeperError> {
        let network_id: [u8; 32] = sha2::Sha256::digest(self.network_passphrase.as_bytes()).into();
        let tx_hash = envelope
            .hash(network_id)
            .map_err(|e| RentkeeperError::Xdr(format!("tx hash: {e}")))?;
        let signature = signing_key.sign(&tx_hash);

        let TransactionEnvelope::Tx(inner) = envelope else {
            return Err(RentkeeperError::Transaction(
                "only v1 envelopes are supported".to_string(),
            ));
        };
        let hint: [u8; 4] = signing_key.verifying_key().to_bytes()[28..]
            .try_into()
            .map_err(|_| RentkeeperError::Key("cannot derive signature hint".to_string()))?;
        let signatures: Vec<DecoratedSignature> = inner.signatures.clone().into();
        let mut signatures = signatures;
        signatures.push(DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(
                signature
                    .to_bytes()
                    .to_vec()
                    .try_into()
                    .map_err(|_| RentkeeperError::Key("signature length".to_string()))?,
            ),
        });
        inner.signatures = VecM::try_from(signatures)
            .map_err(|_| RentkeeperError::Key("too many signatures".to_string()))?;
        Ok(())
    }

    /// Builds and signs in one step.
    ///
    /// # Errors
    /// See [`TxBuilder::build_unsigned`] and [`TxBuilder::sign`].
    pub fn build_signed(
        &self,
        plan: &ArchivalPlan,
        signing_key: &SigningKey,
        seq_num: i64,
    ) -> Result<TransactionEnvelope, RentkeeperError> {
        let public = signing_key.verifying_key().to_bytes();
        let mut envelope = self.build_unsigned(
            plan,
            &PublicKey::PublicKeyTypeEd25519(Uint256(public)),
            seq_num,
        )?;
        self.sign(&mut envelope, signing_key)?;
        Ok(envelope)
    }

    /// Renders an envelope to base64 XDR ready for `sendTransaction`.
    ///
    /// # Errors
    /// Errors when XDR encoding fails.
    pub fn to_xdr_base64(envelope: &TransactionEnvelope) -> Result<String, RentkeeperError> {
        envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| RentkeeperError::Xdr(format!("envelope encode: {e}")))
    }
}

fn pubkey_bytes(source: &PublicKey) -> Result<[u8; 32], RentkeeperError> {
    match source {
        PublicKey::PublicKeyTypeEd25519(bytes) => Ok(bytes.0),
    }
}

/// A fee payer's signing identity parsed from an `S...` secret key.
#[derive(Debug, Clone)]
pub struct FeePayer {
    signing_key: SigningKey,
}

impl FeePayer {
    /// Parses an `S...` Stellar secret seed.
    ///
    /// # Errors
    /// Errors when the string is not a valid Ed25519 secret strkey.
    pub fn from_secret_key_str(secret: &str) -> Result<Self, RentkeeperError> {
        let strkey = stellar_strkey::Strkey::from_string(secret)
            .map_err(|e| RentkeeperError::Key(format!("secret key parse: {e}")))?;
        let bytes = match strkey {
            stellar_strkey::Strkey::PrivateKeyEd25519(private) => private.0,
            _ => {
                return Err(RentkeeperError::Key(
                    "expected an S... secret key, got another strkey type".to_string(),
                ))
            }
        };
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(Self { signing_key })
    }

    /// Creates a payer from raw seed bytes (tests, deterministic tooling).
    #[must_use]
    pub fn from_seed_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    /// The payer's public key bytes.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The payer's `G...` account id strkey.
    #[must_use]
    pub fn account_id_strkey(&self) -> String {
        let strkey = stellar_strkey::Strkey::PublicKeyEd25519(stellar_strkey::ed25519::PublicKey(
            self.public_bytes(),
        ));
        String::from(strkey.to_string().as_str())
    }

    /// The signing key used for signatures.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_keys::LedgerKeys;
    use crate::planner::Planner;
    use crate::ttl::{EntryTtl, RiskWindow, TtlConstants};
    use stellar_xdr::{ContractDataDurability, ScVal};

    fn payer() -> FeePayer {
        FeePayer::from_seed_bytes([42u8; 32])
    }

    fn sample_plan(kind: OperationKind) -> ArchivalPlan {
        let mut cid = [0u8; 32];
        cid[0] = 3;
        let key =
            LedgerKeys::contract_data(&cid, &ScVal::U32(9), ContractDataDurability::Persistent);
        let key_xdr = LedgerKeys::render(&key).expect("render");
        let _ = key_xdr;
        let planner = Planner::new(
            TtlConstants::stellar_public(),
            RiskWindow {
                alert_horizon_ledgers: 1_000,
            },
            "Test SDF Network ; September 2015",
        );
        let plan = match kind {
            OperationKind::Extend => planner
                .plan_extend(
                    &[(
                        key,
                        EntryTtl {
                            current_ledger: 100,
                            live_until_ledger_seq: Some(500),
                        },
                    )],
                    100,
                )
                .expect("plan"),
            OperationKind::Restore => planner
                .plan_restore(
                    &[(
                        key,
                        crate::ttl::ArchivedEntryInfo {
                            current_ledger: 100,
                            archived: true,
                        },
                    )],
                    100,
                )
                .expect("plan"),
        };
        assert!(!plan.is_empty());
        plan
    }

    #[test]
    fn signed_extend_envelope_carries_operation_and_signature() {
        let builder = TxBuilder::new("Test SDF Network ; September 2015");
        let plan = sample_plan(OperationKind::Extend);
        let payer = payer();
        let envelope = builder
            .build_signed(&plan, payer.signing_key(), 1_000)
            .expect("build");

        let TransactionEnvelope::Tx(inner) = &envelope else {
            panic!("expected v1 envelope");
        };
        assert_eq!(inner.tx.operations.len(), 1);
        assert!(matches!(
            inner.tx.operations.first().map(|op| &op.body),
            Some(OperationBody::ExtendFootprintTtl(_))
        ));
        assert_eq!(inner.signatures.len(), 1);

        let b64 = TxBuilder::to_xdr_base64(&envelope).expect("encode");
        assert!(!b64.is_empty());
    }

    #[test]
    fn signed_restore_envelope_carries_restore_op() {
        let builder = TxBuilder::new("Test SDF Network ; September 2015");
        let plan = sample_plan(OperationKind::Restore);
        let payer = payer();
        let envelope = builder
            .build_signed(&plan, payer.signing_key(), 1_000)
            .expect("build");

        let TransactionEnvelope::Tx(inner) = &envelope else {
            panic!("expected v1 envelope");
        };
        assert!(matches!(
            inner.tx.operations.first().map(|op| &op.body),
            Some(OperationBody::RestoreFootprint(_))
        ));
    }

    #[test]
    fn empty_plans_are_rejected() {
        let builder = TxBuilder::new("Test");
        let plan = ArchivalPlan {
            network_passphrase: "Test".to_string(),
            reference_ledger: 1,
            extend_to: 100,
            entries: vec![],
        };
        let payer = payer();
        let err = builder
            .build_signed(&plan, payer.signing_key(), 1)
            .expect_err("must fail");
        assert!(err.to_string().contains("empty plan"));
    }

    #[test]
    fn signature_verifies_against_transaction_hash() {
        let builder = TxBuilder::new("Test SDF Network ; September 2015");
        let plan = sample_plan(OperationKind::Extend);
        let payer = payer();
        let envelope = builder
            .build_signed(&plan, payer.signing_key(), 1_000)
            .expect("build");

        let network_id: [u8; 32] =
            sha2::Sha256::digest("Test SDF Network ; September 2015".as_bytes()).into();
        let tx_hash = envelope.hash(network_id).expect("hash");
        let TransactionEnvelope::Tx(inner) = &envelope else {
            panic!("expected v1 envelope");
        };
        let sig = &inner.signatures.first().expect("sig").signature;
        use ed25519_dalek::Verifier as _;
        payer
            .signing_key()
            .verifying_key()
            .verify(
                &tx_hash,
                &ed25519_dalek::Signature::from_bytes(
                    &sig.0.to_vec()[..].try_into().expect("64 bytes"),
                ),
            )
            .expect("signature must verify");
    }

    #[test]
    fn fee_payer_roundtrips_secret_strkey() {
        let payer = payer();
        // Rebuild a secret strkey from the seed and parse it back.
        let secret = stellar_strkey::Strkey::PrivateKeyEd25519(
            stellar_strkey::ed25519::PrivateKey(payer.signing_key().to_bytes()),
        );
        let secret = String::from(secret.to_string().as_str());
        assert!(secret.starts_with('S'));
        let parsed = FeePayer::from_secret_key_str(&secret).expect("parse");
        assert_eq!(parsed.public_bytes(), payer.public_bytes());
        assert!(payer.account_id_strkey().starts_with('G'));
    }

    #[test]
    fn wrong_strkey_type_is_rejected() {
        let payer = payer();
        let account = payer.account_id_strkey();
        assert!(FeePayer::from_secret_key_str(&account).is_err());
    }

    #[test]
    fn oversize_plans_are_rejected() {
        let builder = TxBuilder::new("Test");
        let mut entries = Vec::new();
        for i in 0..101u8 {
            let mut cid = [0u8; 32];
            cid[0] = i;
            let key = LedgerKeys::contract_data(
                &cid,
                &ScVal::U32(u32::from(i)),
                ContractDataDurability::Persistent,
            );
            entries.push(crate::plan::PlanEntry {
                key_xdr: LedgerKeys::render(&key).expect("render"),
                key,
                kind: OperationKind::Extend,
                durability: Some(crate::ttl::Durability::Persistent),
                ttl: EntryTtl {
                    current_ledger: 1,
                    live_until_ledger_seq: Some(2),
                },
            });
        }
        let plan = ArchivalPlan {
            network_passphrase: "Test".to_string(),
            reference_ledger: 1,
            extend_to: 100,
            entries,
        };
        let payer = payer();
        let err = builder
            .build_signed(&plan, payer.signing_key(), 1)
            .expect_err("must fail");
        assert!(err.to_string().contains("at most 100"));
    }
}
