use signer_core::bls::{SecretKey, public_key, sign};
use signer_core::eip2333;
use zeroize::Zeroize;

use crate::micropython::buffer::get_buffer;
use crate::micropython::module::Module;
use crate::micropython::qstr::Qstr;
use crate::micropython::tracked_allocator::with_alloc;
use crate::micropython::{util, Error, Obj};

/// Accepted seed length range. BIP-39 and SLIP-39 seeds are 64 bytes; the
/// lower bound is a sanity floor (EIP-2333 itself requires at least 32 bytes
/// and shorter seeds are rejected during derivation).
const SEED_MIN_LEN: usize = 16;
const SEED_MAX_LEN: usize = 64;

/// Consensus signing roots are always 32 bytes (an SSZ merkle root).
const SIGNING_ROOT_LEN: usize = 32;

fn check_seed_len(seed: &[u8]) -> Result<(), Error> {
    if !(SEED_MIN_LEN..=SEED_MAX_LEN).contains(&seed.len()) {
        return Err(Error::ValueError(c"Invalid seed length (16 to 64 bytes)"));
    }
    Ok(())
}

fn check_signing_root_len(signing_root: &[u8]) -> Result<(), Error> {
    if signing_root.len() != SIGNING_ROOT_LEN {
        return Err(Error::ValueError(c"Signing root must be 32 bytes"));
    }
    Ok(())
}

/// Derive the EIP-2334 validator signing key `m/12381/3600/index/0/0` from
/// `seed`. The secret key never leaves this module: callers use it and the
/// copies here are zeroized.
fn derive_secret_key(seed: &[u8], index: u32) -> Result<SecretKey, Error> {
    let mut sk_bytes = eip2333::validator_signing_key(seed, index)
        .map_err(|_| Error::ValueError(c"Failed to derive BLS key"))?;
    let secret_key = SecretKey::from_bytes(sk_bytes)
        .map_err(|_| Error::ValueError(c"Failed to derive BLS key"))?;
    sk_bytes.zeroize();
    Ok(secret_key)
}

extern "C" fn bls_public_key(seed: Obj, index: Obj) -> Obj {
    let block = || {
        // SAFETY: references are discarded at the end of this block.
        let seed = unsafe { get_buffer(seed)? };
        let index: u32 = index.try_into()?;
        check_seed_len(seed)?;
        // signer-core/blst allocate: all heap use stays inside `with_alloc`
        // and nothing heap-owned escapes it (the result is a plain array).
        let pubkey: [u8; 48] = with_alloc(|| -> Result<[u8; 48], Error> {
            let secret_key = derive_secret_key(seed, index)?;
            Ok(*public_key(&secret_key).as_bytes())
        })?;
        pubkey.as_slice().try_into()
    };
    unsafe { util::try_or_raise(block) }
}

extern "C" fn bls_sign(seed: Obj, index: Obj, signing_root: Obj) -> Obj {
    let block = || {
        // SAFETY: references are discarded at the end of this block.
        let (seed, signing_root) = unsafe { (get_buffer(seed)?, get_buffer(signing_root)?) };
        let index: u32 = index.try_into()?;
        check_seed_len(seed)?;
        check_signing_root_len(signing_root)?;
        let root: [u8; SIGNING_ROOT_LEN] = signing_root
            .try_into()
            .map_err(|_| Error::ValueError(c"Signing root must be 32 bytes"))?;
        let signature: [u8; 96] = with_alloc(|| -> Result<[u8; 96], Error> {
            let secret_key = derive_secret_key(seed, index)?;
            Ok(sign(&secret_key, &root))
        })?;
        signature.as_slice().try_into()
    };
    unsafe { util::try_or_raise(block) }
}

#[no_mangle]
#[rustfmt::skip]
pub static mp_module_trezorbls: Module = obj_module! {
    Qstr::MP_QSTR___name__ => Qstr::MP_QSTR_trezorbls.to_obj(),

    /// def public_key(seed: AnyBytes, index: int) -> bytes:
    ///     """
    ///     Derive the EIP-2334 validator signing key m/12381/3600/index/0/0
    ///     from `seed` and return its 48-byte compressed BLS12-381 public key.
    ///     The secret key is never exposed to Python.
    ///     """
    Qstr::MP_QSTR_public_key => obj_fn_2!(bls_public_key).as_obj(),

    /// def sign(seed: AnyBytes, index: int, signing_root: bytes) -> bytes:
    ///     """
    ///     Sign the 32-byte consensus `signing_root` with the validator key
    ///     at m/12381/3600/index/0/0 derived from `seed`, and return the
    ///     96-byte compressed BLS12-381 signature. The secret key is derived,
    ///     used and zeroized inside; it is never returned to Python.
    ///     """
    Qstr::MP_QSTR_sign => obj_fn_3!(bls_sign).as_obj(),
};
