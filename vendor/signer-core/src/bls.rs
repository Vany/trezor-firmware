//! BLS12-381 signing over [blst] (`min_pk` scheme: 48-byte compressed
//! public keys, 96-byte compressed signatures).
//!
//! Signatures use the ciphersuite required by consensus-specs:
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` — hash-to-curve with
//! SHA-256, random oracle, proof-of-possession variant, empty augmentation.
//!
//! blst compiles as `no_std` (it declares `#![cfg_attr(not(feature = "std"),
//! no_std)]` and ships no `std` cargo feature), but its build script
//! compiles C and it links libc, so a bare-metal firmware needs a working C
//! toolchain for the target. The `bls` feature (default) can be turned off
//! to build everything else without it.
//!
//! [blst]: https://crates.io/crates/blst

use blst::min_pk::{
    PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature,
};
use blst::BLST_ERROR;
use core::fmt;
use zeroize::Zeroize;

use crate::types::PubKey;

/// The consensus-specs BLS ciphersuite DST (proof of possession).
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Errors from BLS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlsError {
    /// Secret key bytes are not a valid scalar (`0 < sk < r`).
    InvalidSecretKey,
    /// Public key bytes do not deserialize to a valid G1 point.
    InvalidPublicKey,
    /// Signature bytes do not deserialize to a valid G2 point.
    InvalidSignature,
}

impl fmt::Display for BlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlsError::InvalidSecretKey => {
                write!(f, "invalid BLS secret key (must satisfy 0 < sk < r)")
            }
            BlsError::InvalidPublicKey => write!(f, "invalid BLS public key"),
            BlsError::InvalidSignature => write!(f, "invalid BLS signature"),
        }
    }
}

/// A BLS12-381 secret key: 32 **big-endian** bytes in `[1, r)` — the same
/// byte order as blst's Rust `SecretKey::from_bytes`/`to_bytes`.
///
/// The raw bytes are zeroized when the key is dropped. Wrap keys in an
/// `Arc`/clone-free structure where possible: cloning copies the bytes, and
/// each copy zeroizes itself independently.
#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Wrap validated secret-key bytes. The scalar must satisfy
    /// `0 < sk < r`; this crate checks the range itself because blst's
    /// deserializer silently reduces out-of-range scalars modulo `r`.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, BlsError> {
        if !crate::eip2333::is_valid_scalar_be(&bytes) {
            return Err(BlsError::InvalidSecretKey);
        }
        BlstSecretKey::from_bytes(&bytes).map_err(|_| BlsError::InvalidSecretKey)?;
        Ok(Self(bytes))
    }

    /// Raw big-endian bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn blst(&self) -> BlstSecretKey {
        // Infallible: construction validated the bytes.
        BlstSecretKey::from_bytes(&self.0).expect("validated at construction")
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material, not even byte counts that hint at it.
        f.write_str("SecretKey(<zeroized on drop>)")
    }
}

/// Derive the 48-byte compressed public key for `sk`.
pub fn public_key(sk: &SecretKey) -> PubKey {
    PubKey::from_bytes(sk.blst().sk_to_pk().compress())
}

/// Sign the 32-byte signing root (consensus-specs `bls.Sign`), returning the
/// 96-byte compressed signature.
pub fn sign(sk: &SecretKey, signing_root: &[u8; 32]) -> [u8; 96] {
    sk.blst().sign(signing_root, DST, &[]).compress()
}

/// Verify a signature over the signing root (consensus-specs `bls.Verify`).
/// Returns `false` on any invalid input (never panics on bad points).
pub fn verify(public_key: &PubKey, signature: &[u8; 96], signing_root: &[u8; 32]) -> bool {
    let Ok(pk) = BlstPublicKey::from_bytes(public_key.as_bytes()) else {
        return false;
    };
    let Ok(sig) = BlstSignature::from_bytes(signature) else {
        return false;
    };
    matches!(
        sig.verify(false, signing_root, DST, &[], &pk, false),
        BLST_ERROR::BLST_SUCCESS
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eip2333::validator_signing_key;

    // Seed from EIP-2333 test case 1 (see eip2333.rs).
    const SEED: &str = "0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    fn test_key() -> SecretKey {
        let bytes = validator_signing_key(crate::testing::unhex(SEED).as_slice(), 0).unwrap();
        SecretKey::from_bytes(bytes).unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = test_key();
        let pk = public_key(&sk);
        let message = [0xab; 32];
        let signature = sign(&sk, &message);
        assert!(verify(&pk, &signature, &message));
    }

    #[test]
    fn verify_rejects_wrong_message_and_tampered_signature() {
        let sk = test_key();
        let pk = public_key(&sk);
        let message = [0xcd; 32];
        let mut signature = sign(&sk, &message);
        assert!(!verify(&pk, &signature, &[0xce; 32]));
        signature[0] ^= 0x01;
        assert!(!verify(&pk, &signature, &message));
    }

    #[test]
    fn verify_rejects_wrong_pubkey_and_garbage_points() {
        let sk = test_key();
        let message = [0x00; 32];
        let signature = sign(&sk, &message);
        let wrong_pk = public_key(
            &SecretKey::from_bytes(
                validator_signing_key(crate::testing::unhex(SEED).as_slice(), 1).unwrap(),
            )
            .unwrap(),
        );
        assert!(!verify(&wrong_pk, &signature, &message));

        let all_zero_pk = PubKey::from_bytes([0; 48]);
        assert!(!verify(&all_zero_pk, &signature, &message));
        assert!(!verify(&public_key(&sk), &[0xff; 96], &message));
    }

    #[test]
    fn secret_key_validation_and_zeroize() {
        assert_eq!(
            SecretKey::from_bytes([0; 32]).unwrap_err(),
            BlsError::InvalidSecretKey
        );
        // r itself is out of range.
        assert_eq!(
            SecretKey::from_bytes(crate::eip2333::R_BYTES_BE).unwrap_err(),
            BlsError::InvalidSecretKey
        );

        let mut sk = test_key();
        let before = *sk.as_bytes();
        sk.zeroize();
        assert_eq!(*sk.as_bytes(), [0u8; 32]);
        assert!(before != [0u8; 32]);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let sk = test_key();
        assert_eq!(alloc::format!("{sk:?}"), "SecretKey(<zeroized on drop>)");
    }

    #[test]
    fn derivation_agrees_with_blst_eip2333() {
        // Cross-check our EIP-2333 child derivation against blst's own
        // (which also proves our little-endian key encoding is the one blst
        // signs with).
        let seed = crate::testing::unhex(SEED);
        let master = crate::eip2333::derive_master_sk(&seed).unwrap();
        for index in [0u32, 1, 42, u32::MAX] {
            let ours = crate::eip2333::derive_child_sk(&master, index);
            let blst_parent = BlstSecretKey::from_bytes(&master).expect("valid master");
            let blst_child = blst_parent.derive_child_eip2333(index);
            assert_eq!(ours.as_slice(), blst_child.to_bytes(), "index {index}");
        }
    }
}
