// SPDX-License-Identifier: Apache-2.0
//! Seal-owned Ed25519 verification invariants.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// The Ed25519 group order `L`, encoded little-endian.
///
/// RFC 8032 section 5.1.7 requires the signature scalar `S` to be in
/// `[0, L)`. Keep this check at seal's boundary: dependency features may
/// otherwise relax the accepted scalar range.
const GROUP_ORDER_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerificationError {
    NonCanonicalScalar,
    Mismatch,
}

/// Verify an Ed25519 signature after enforcing seal's RFC 8032 scalar range.
pub(crate) fn verify(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), VerificationError> {
    let bytes = signature.to_bytes();
    let scalar = &bytes[32..];
    if scalar.iter().rev().cmp(GROUP_ORDER_L.iter().rev()).is_ge() {
        return Err(VerificationError::NonCanonicalScalar);
    }

    key.verify(message, signature)
        .map_err(|_| VerificationError::Mismatch)
}
