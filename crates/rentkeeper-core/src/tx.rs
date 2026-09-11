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
