from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import Eth2GetPublicKey, Eth2PublicKey


async def get_public_key(msg: Eth2GetPublicKey) -> Eth2PublicKey:
    """Return the BLS12-381 public key of the validator signing key.

    The key is derived from the device seed via EIP-2333/EIP-2334 at
    m/12381/3600/validator_index/0/0. The secret key never leaves the
    BLS module.
    """
    from trezor.messages import Eth2PublicKey

    from apps.common.seed import get_seed, raise_if_not_initialized

    raise_if_not_initialized()

    import trezorbls

    seed = await get_seed()
    pubkey = trezorbls.public_key(seed, msg.validator_index)
    return Eth2PublicKey(pubkey=pubkey)
