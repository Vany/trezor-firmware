//! Minimal SSZ merkleization, hand-written for the fixed-size consensus
//! containers this crate signs (see consensus-specs `ssz/simple-serialize.md`).
//!
//! Only what signing roots need:
//! - packing a `uint64` into a 32-byte chunk (little-endian, zero-padded),
//! - padding short byte vectors (`Vector[byte, N]` with `N <= 32`) into a
//!   chunk,
//! - merkleizing a list of chunks up to the next power of two (zero-padded).
//!
//! Variable-size types (lists with mix-in length) are deliberately not
//! implemented; nothing we sign needs them.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// SSZ chunk size in bytes.
pub const BYTES_PER_CHUNK: usize = 32;

/// SHA-256 of the concatenation of two chunks (one tree node).
fn hash_pair(a: &[u8; BYTES_PER_CHUNK], b: &[u8; BYTES_PER_CHUNK]) -> [u8; BYTES_PER_CHUNK] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// Pack a `uint64` into a chunk: 8 little-endian bytes, zero-padded to 32.
pub fn uint64_chunk(value: u64) -> [u8; BYTES_PER_CHUNK] {
    let mut chunk = [0u8; BYTES_PER_CHUNK];
    chunk[..8].copy_from_slice(&value.to_le_bytes());
    chunk
}

/// Right-pad `bytes` (at most one chunk's worth) with zeros into a chunk.
/// This is the packed form of `Vector[byte, N]` for `N <= 32`.
///
/// # Panics
/// Panics if `bytes.len() > 32`.
pub fn byte_vector_chunk(bytes: &[u8]) -> [u8; BYTES_PER_CHUNK] {
    assert!(
        bytes.len() <= BYTES_PER_CHUNK,
        "byte vector spans multiple chunks"
    );
    let mut chunk = [0u8; BYTES_PER_CHUNK];
    chunk[..bytes.len()].copy_from_slice(bytes);
    chunk
}

/// Merkleize `chunks` after zero-padding to the next power of two (minimum
/// one leaf). This is the container rule: a container with N fields has
/// `next_pow_of_two(N)` leaves.
pub fn merkleize(chunks: &[[u8; BYTES_PER_CHUNK]]) -> [u8; BYTES_PER_CHUNK] {
    let width = chunks.len().max(1).next_power_of_two();
    let mut layer: Vec<[u8; BYTES_PER_CHUNK]> = Vec::with_capacity(width);
    layer.extend_from_slice(chunks);
    layer.resize(width, [0u8; BYTES_PER_CHUNK]);
    while layer.len() > 1 {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();
    }
    layer[0]
}

/// The SSZ hash-tree-root operation, implemented for the fixed-size types
/// used as container fields in this crate.
pub trait HashTreeRoot {
    /// Merkleized SSZ hash tree root.
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK];
}

impl HashTreeRoot for u64 {
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        uint64_chunk(*self)
    }
}

/// `Vector[byte, 4]`: fork versions and domain types.
impl HashTreeRoot for [u8; 4] {
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        byte_vector_chunk(self)
    }
}

/// `Bytes32`: roots, public keys' tree leaves, and domains.
impl HashTreeRoot for [u8; 32] {
    fn hash_tree_root(&self) -> [u8; BYTES_PER_CHUNK] {
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint64_chunk_is_little_endian_padded() {
        assert_eq!(uint64_chunk(1)[..8], [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            uint64_chunk(0x0102030405060708)[..8],
            [8, 7, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(uint64_chunk(7)[8..], [0u8; 24]);
    }

    #[test]
    fn two_chunks_merkleize_to_sha256_pair() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        assert_eq!(merkleize(&[a, b]), hash_pair(&a, &b));
    }

    #[test]
    fn five_chunks_are_padded_to_eight_leaves() {
        // 5 field roots + 3 zero chunks, then three rounds of pairing.
        let leaves: Vec<[u8; 32]> = (0u8..5).map(|i| [i + 1; 32]).collect();
        let mut padded: Vec<[u8; 32]> = leaves.clone();
        padded.resize(8, [0; 32]);
        let mut layer = padded;
        while layer.len() > 1 {
            layer = layer
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| hash_pair(&p[0], &p[1]))
                .collect();
        }
        assert_eq!(merkleize(&leaves), layer[0]);
    }
}
