//! `signer-core`: the signing logic shared by the remote-signing router and
//! the hardware wallet firmware (no_std + alloc, no OS, no RNG).
//!
//! Modules:
//! - [`ssz`]: minimal SSZ merkleization ([`HashTreeRoot`](ssz::HashTreeRoot)).
//! - [`types`]: the consensus-specs containers we sign, with
//!   [`HashTreeRoot`](ssz::HashTreeRoot) implementations.
//! - [`domains`]: domain constants, `compute_domain`, `compute_signing_root`,
//!   and fork-version selection (consensus-specs `get_domain`).
//! - [`slashing`]: EIP-3076 slashing protection ([`SlashingDb`](slashing::SlashingDb))
//!   with a bounded in-memory implementation.
//! - [`eip2333`]: EIP-2333 BLS12-381 key derivation and the EIP-2334
//!   `m/12381/3600/i/0/0` validator signing-key path.
//! - [`bls`] (feature `bls`, default): BLS12-381 sign/verify over blst
//!   (min_pk, ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`).
//!
//! Everything here is deterministic; the crate never needs an RNG.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod domains;
pub mod eip2333;
pub mod slashing;
pub mod ssz;
pub mod types;

#[cfg(feature = "bls")]
pub mod bls;

/// Hex decoding for test vectors (test-only; hex strings in vectors are
/// written without whitespace).
#[cfg(test)]
pub(crate) mod testing {
    /// Decode a hex string, tolerating an optional `0x` prefix.
    pub fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        let body = s.strip_prefix("0x").unwrap_or(s);
        assert!(body.len().is_multiple_of(2), "odd hex length: {s}");
        let mut out = alloc::vec::Vec::with_capacity(body.len() / 2);
        let bytes = body.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = hex_nibble(bytes[i]).expect("valid hex");
            let lo = hex_nibble(bytes[i + 1]).expect("valid hex");
            out.push(hi << 4 | lo);
        }
        out
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
}
