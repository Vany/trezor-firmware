from typing import *
from buffer_types import *


# rust/src/micropython/bls.rs
def public_key(seed: AnyBytes, index: int) -> bytes:
    """
    Derive the EIP-2334 validator signing key m/12381/3600/index/0/0
    from `seed` and return its 48-byte compressed BLS12-381 public key.
    The secret key is never exposed to Python.
    """


# rust/src/micropython/bls.rs
def sign(seed: AnyBytes, index: int, signing_root: bytes) -> bytes:
    """
    Sign the 32-byte consensus `signing_root` with the validator key
    at m/12381/3600/index/0/0 derived from `seed`, and return the
    96-byte compressed BLS12-381 signature. The secret key is derived,
    used and zeroized inside; it is never returned to Python.
    """
