//! EIP-2333 BLS12-381 hierarchical key derivation and the EIP-2334
//! `m/12381/3600/i/0/0` validator signing-key path.
//!
//! Sources: <https://eips.ethereum.org/EIPS/eip-2333> (test vectors below
//! are copied from its "Test cases" section) and
//! <https://eips.ethereum.org/EIPS/eip-2334>.
//!
//! Secret keys are 32-byte **big-endian** integers in `[1, r)`, where `r`
//! is the BLS12-381 subgroup order. This matches the EIP's I2OSP/OS2IP
//! conventions and the byte interface of blst's Rust bindings
//! (`SecretKey::from_bytes`/`to_bytes`), which is what [`crate::bls`] uses
//! to sign. This module is `no_std` and pulls in no BLS library: the
//! modular reduction `OS2IP(OKM) mod r` is implemented locally with
//! 256-bit shift-subtract division.
//!
//! The division is not constant-time. Its inputs are HKDF outputs derived
//! from the seed, not the seed itself; on a hardware wallet the derivation
//! routines run inside the secure context anyway.

use alloc::vec::Vec;
use core::fmt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// `r`, the order of the BLS12-381 G1 subgroup, big-endian.
pub(crate) const R_BYTES_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// `r` as four little-endian u64 limbs, derived from [`R_BYTES_BE`] in a
/// const fn so the two forms cannot drift apart.
const R_LIMBS: [u64; 4] = limbs_from_be(R_BYTES_BE);

const fn limbs_from_be(bytes: [u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    let mut group = 0;
    while group < 4 {
        let mut word: u64 = 0;
        let mut offset = 0;
        while offset < 8 {
            word = (word << 8) | bytes[group * 8 + offset] as u64;
            offset += 1;
        }
        limbs[3 - group] = word;
        group += 1;
    }
    limbs
}

/// HKDF-salt used by the KeyGen function of the IETF BLS signature draft.
const KEYGEN_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

/// Length of one Lamport private-key chunk list (255 chunks of 32 bytes, the
/// HKDF-Expand length limit for SHA-256).
const LAMPORT_CHUNKS: usize = 255;

/// Errors from key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveError {
    /// EIP-2333 requires `len(seed) >= 32`.
    SeedTooShort(usize),
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeriveError::SeedTooShort(len) => {
                write!(f, "seed must be at least 32 bytes, got {len}")
            }
        }
    }
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut okm: Vec<u8> = Vec::with_capacity(length);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u16 = 1;
    while okm.len() < length {
        assert!(counter <= 255, "HKDF length beyond 255 blocks of 32 bytes");
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter as u8]);
        let block = mac.finalize().into_bytes();
        previous = block.to_vec();
        okm.extend_from_slice(&block);
        counter += 1;
    }
    okm.truncate(length);
    okm
}

fn limb_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn limb_sub_assign(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff, b2) = diff.overflowing_sub(borrow);
        a[i] = diff;
        borrow = (b1 as u64) | (b2 as u64);
    }
}

/// `value mod r` for a 320-bit little-endian limb value, via binary
/// (shift-subtract) long division.
fn mod_r_320(value: &[u64; 5]) -> [u64; 4] {
    let mut rem = [0u64; 4];
    for bit_index in (0..320).rev() {
        // rem = (rem << 1) | bit(value, bit_index), tracking the overflow bit.
        let limb = bit_index / 64;
        let bit = (value[limb] >> (bit_index % 64)) & 1;
        let mut carry = bit;
        for word in rem.iter_mut() {
            let next_carry = *word >> 63;
            *word = (*word << 1) | carry;
            carry = next_carry;
        }
        if carry == 1 || limb_ge(&rem, &R_LIMBS) {
            limb_sub_assign(&mut rem, &R_LIMBS);
        }
    }
    rem
}

/// Interpret `bytes` as a big-endian integer and reduce it modulo `r`,
/// returning the canonical 32-byte big-endian secret key form.
fn mod_r_be(bytes: &[u8]) -> [u8; 32] {
    let mut acc = [0u64; 4];
    for &byte in bytes {
        // acc = (acc << 8) | byte, as a 320-bit value.
        let mut value = [0u64; 5];
        let mut carry = byte as u64;
        for i in 0..4 {
            value[i] = (acc[i] << 8) | carry;
            carry = acc[i] >> 56;
        }
        value[4] = carry;
        acc = mod_r_320(&value);
    }
    // acc is little-endian limbs; emit big-endian bytes, most significant
    // limb first.
    let mut out = [0u8; 32];
    for (i, limb) in acc.iter().rev().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// True when `bytes` (big-endian) is a valid BLS secret-key scalar: nonzero
/// and strictly below the group order `r`.
pub fn is_valid_scalar_be(bytes: &[u8; 32]) -> bool {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        // Big-endian input: the first 8 bytes are the most significant limb.
        limbs[3 - i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().expect("8 bytes"));
    }
    limbs != [0; 4] && !limb_ge(&limbs, &R_LIMBS)
}

/// `HKDF_mod_r` (EIP-2333 / IETF KeyGen): reduce a 48-byte HKDF output
/// modulo `r`, retrying with a re-hashed salt if the result is zero.
fn hkdf_mod_r(ikm: &[u8], key_info: &[u8]) -> [u8; 32] {
    const L: usize = 48;
    let mut salt: Vec<u8> = KEYGEN_SALT.to_vec();
    loop {
        salt = Sha256::digest(&salt).to_vec();
        let mut mac_ikm = Vec::with_capacity(ikm.len() + 1);
        mac_ikm.extend_from_slice(ikm);
        mac_ikm.push(0); // IKM || I2OSP(0, 1)
        let prk = hkdf_extract(&salt, &mac_ikm);
        mac_ikm.zeroize();
        let mut info = Vec::with_capacity(key_info.len() + 2);
        info.extend_from_slice(key_info);
        info.extend_from_slice(&(L as u16).to_be_bytes());
        let okm = hkdf_expand(&prk, &info, L);
        drop(info);
        let sk = mod_r_be(&okm);
        if sk != [0u8; 32] {
            return sk;
        }
    }
}

fn ikm_to_lamport_sk(ikm: &[u8; 32], salt: &[u8; 4]) -> Vec<u8> {
    // EIP-2333 IKM_to_lamport_SK: HKDF with the raw 4-byte index salt
    // (no pre-hashing of the salt, unlike hkdf_mod_r).
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, &[], LAMPORT_CHUNKS * 32)
}

/// `parent_SK_to_lamport_PK` (EIP-2333): the compressed Lamport public key
/// used as the derivation entropy for a child key. `parent_sk` is the
/// 32-byte big-endian parent scalar, per the EIP's `IKM = I2OSP(parent_SK, 32)`.
pub fn parent_sk_to_lamport_pk(parent_sk: &[u8; 32], index: u32) -> [u8; 32] {
    let salt = index.to_be_bytes();
    let mut not_ikm = *parent_sk;
    for byte in not_ikm.iter_mut() {
        *byte = !*byte;
    }
    let mut lamport_0 = ikm_to_lamport_sk(parent_sk, &salt);
    let mut lamport_1 = ikm_to_lamport_sk(&not_ikm, &salt);
    not_ikm.zeroize();

    let mut hasher = Sha256::new();
    let lamport_0_chunks = lamport_0.as_chunks::<32>().0;
    let lamport_1_chunks = lamport_1.as_chunks::<32>().0;
    for chunk in lamport_0_chunks.iter().chain(lamport_1_chunks.iter()) {
        hasher.update(Sha256::digest(chunk));
    }
    lamport_0.zeroize();
    lamport_1.zeroize();
    hasher.finalize().into()
}

/// `derive_master_SK` (EIP-2333): the tree root key for a seed of at least
/// 32 bytes (BIP-39 `mnemonic_to_seed` output is the usual source).
pub fn derive_master_sk(seed: &[u8]) -> Result<[u8; 32], DeriveError> {
    if seed.len() < 32 {
        return Err(DeriveError::SeedTooShort(seed.len()));
    }
    Ok(hkdf_mod_r(seed, &[]))
}

/// `derive_child_SK` (EIP-2333): child `index` of `parent_sk`.
pub fn derive_child_sk(parent_sk: &[u8; 32], index: u32) -> [u8; 32] {
    let compressed_lamport_pk = parent_sk_to_lamport_pk(parent_sk, index);
    hkdf_mod_r(&compressed_lamport_pk, &[])
}

/// Derive through a path of child indices, e.g. `[12381, 3600, 0, 0, 0]`
/// for `m/12381/3600/0/0/0`.
pub fn derive_path(master_sk: &[u8; 32], path: &[u32]) -> [u8; 32] {
    let mut sk = *master_sk;
    for &index in path {
        sk = derive_child_sk(&sk, index);
    }
    sk
}

/// EIP-2334: the validator signing key at `m/12381/3600/{account}/0/0`
/// (purpose 12381, coin type 3600, account, use 0, index 0).
pub fn validator_signing_key(seed: &[u8], account: u32) -> Result<[u8; 32], DeriveError> {
    let master = derive_master_sk(seed)?;
    Ok(derive_path(&master, &[12381, 3600, account, 0, 0]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::unhex;

    fn arr32(hex: &str) -> [u8; 32] {
        unhex(hex).try_into().expect("32 bytes")
    }

    #[test]
    fn r_limbs_match_big_endian_bytes() {
        let groups = R_BYTES_BE.as_chunks::<8>().0;
        let limbs: Vec<u64> = groups
            .iter()
            .map(|c| u64::from_be_bytes(*c))
            .rev()
            .collect();
        assert_eq!(limbs.as_slice(), R_LIMBS);
    }

    /// Big-endian subtraction of 1.
    fn be_dec(v: &[u8]) -> Vec<u8> {
        let mut out = v.to_vec();
        for b in out.iter_mut().rev() {
            if *b == 0 {
                *b = 0xff;
            } else {
                *b -= 1;
                break;
            }
        }
        out
    }

    /// Big-endian addition (returns one byte longer than the inputs).
    fn be_add_wide(a: &[u8], b: &[u8]) -> Vec<u8> {
        assert_eq!(a.len(), b.len());
        let mut out = alloc::vec![0u8; a.len() + 1];
        let mut carry = 0u16;
        for i in (0..a.len()).rev() {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            out[i + 1] = sum as u8;
            carry = sum >> 8;
        }
        out[0] = carry as u8;
        out
    }

    #[test]
    fn mod_r_boundaries() {
        // Small values pass through unchanged in big-endian form.
        let mut five = alloc::vec![0u8; 31];
        five.push(5);
        let mut five_be = [0u8; 32];
        five_be[31] = 5;
        assert_eq!(mod_r_be(&five), five_be);

        // r maps to 0, r - 1 maps to itself.
        let r_minus_1 = be_dec(&R_BYTES_BE);
        let r_minus_2 = be_dec(&r_minus_1);
        let arr32 = |v: &[u8]| -> [u8; 32] { v.try_into().expect("32 bytes") };
        assert_eq!(mod_r_be(&R_BYTES_BE), [0u8; 32]);
        assert_eq!(mod_r_be(&r_minus_1), arr32(&r_minus_1));

        // (r - 1) + (r - 1) = 2r - 2 reduces to r - 2, exercising the
        // multi-limb path of the division (2r still fits in 48 bytes).
        let two_r_minus_2 = be_add_wide(&r_minus_1, &r_minus_1);
        assert_eq!(two_r_minus_2[0], 0x00, "2r - 2 fits in 48 bytes");
        assert_eq!(mod_r_be(&two_r_minus_2[1..]), arr32(&r_minus_2));
    }

    // ------------------------------------------------------------------
    // Test vectors from EIP-2333 "Test cases"
    // (https://eips.ethereum.org/EIPS/eip-2333). The EIP lists secret keys
    // as decimal integers; below they are encoded as 32-byte big-endian hex
    // (e.g. case 1's master_SK 608387445470927092834538627449860504498664
    // 0685124978867557563392430687146096 -> 0x0d7359d5...).
    // ------------------------------------------------------------------

    struct Vector {
        seed: &'static str,
        master_sk: &'static str,
        child_index: u32,
        child_sk: &'static str,
    }

    const VECTORS: &[Vector] = &[
        // case 1 (child_index 0)
        Vector {
            seed: "0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            master_sk: "0x0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070",
            child_index: 0,
            child_sk: "0x2d18bd6c14e6d15bf8b5085c9b74f3daae3b03cc2014770a599d8c1539e50f8e",
        },
        // case 2 (child_index 3141592653)
        Vector {
            seed: "0x3141592653589793238462643383279502884197169399375105820974944592",
            master_sk: "0x41c9e07822b092a93fd6797396338c3ada4170cc81829fdfce6b5d34bd5e7ec7",
            child_index: 3141592653,
            child_sk: "0x384843fad5f3d777ea39de3e47a8f999ae91f89e42bffa993d91d9782d152a0f",
        },
        // case 3 (child_index 4294967295)
        Vector {
            seed: "0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
            master_sk: "0x3cfa341ab3910a7d00d933d8f7c4fe87c91798a0397421d6b19fd5b815132e80",
            child_index: 4294967295,
            child_sk: "0x40e86285582f35b28821340f6a53b448588efa575bc4d88c32ef8567b8d9479b",
        },
        // case 4 (child_index 42)
        Vector {
            seed: "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            master_sk: "0x2a0e28ffa5fbbe2f8e7aad4ed94f745d6bf755c51182e119bb1694fe61d3afca",
            child_index: 42,
            child_sk: "0x455c0dc9fccb3395825d92a60d2672d69416be1c2578a87a7a3d3ced11ebb88d",
        },
    ];

    #[test]
    fn eip2333_all_vectors() {
        for v in VECTORS {
            let master = derive_master_sk(&unhex(v.seed)).expect("seed length ok");
            assert_eq!(
                master,
                arr32(v.master_sk),
                "master SK mismatch for seed {}",
                v.seed
            );
            let child = derive_child_sk(&master, v.child_index);
            assert_eq!(
                child,
                arr32(v.child_sk),
                "child SK mismatch for index {}",
                v.child_index
            );
        }
    }

    #[test]
    fn eip2333_case1_lamport_compressed_pk_vector() {
        // Case 1 of EIP-2333 also publishes the two 255-chunk Lamport secret
        // keys and their compressed public key. The compression is the SHA-256
        // over every published chunk, so this check pins the entire chain:
        // any deviation in HKDF, chunking, or the final hash misses it.
        let master = derive_master_sk(&unhex(VECTORS[0].seed)).unwrap();
        assert_eq!(
            parent_sk_to_lamport_pk(&master, 0),
            arr32("0xdd635d27d1d52b9a49df9e5c0c622360a4dd17cba7db4e89bce3cb048fb721a5")
        );
    }

    #[test]
    fn eip2333_short_seed_is_rejected() {
        assert_eq!(
            derive_master_sk(&[0u8; 31]),
            Err(DeriveError::SeedTooShort(31))
        );
        assert!(derive_master_sk(&[0u8; 32]).is_ok());
    }

    #[test]
    fn eip2334_path_is_sequential_derivation() {
        let seed = unhex(VECTORS[0].seed);
        let account = 7;
        let via_path = validator_signing_key(&seed, account).unwrap();
        let manual = derive_path(
            &derive_master_sk(&seed).unwrap(),
            &[12381, 3600, account, 0, 0],
        );
        assert_eq!(via_path, manual);
        // Different accounts derive different keys.
        assert_ne!(via_path, validator_signing_key(&seed, account + 1).unwrap());
    }
}
