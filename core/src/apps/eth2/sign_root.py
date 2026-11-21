from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import Eth2SignRoot, Eth2Signature

# Whether the user already approved validator signing in this session is kept
# in the session cache (APP_ETH2_SIGNING_CONFIRMED): app modules are unloaded
# after every workflow, so a module global would reset on each message. A
# validator signs every epoch, so we ask once per session, not per message.


async def sign_root(msg: Eth2SignRoot) -> Eth2Signature:
    """Sign a 32-byte consensus signing root with the validator signing key.

    The key is derived from the device seed via EIP-2333/EIP-2334 at
    m/12381/3600/validator_index/0/0. The secret key is derived, used and
    zeroized inside the BLS module; it never reaches Python.
    """
    from trezor.messages import Eth2Signature
    from trezor.ui.layouts import confirm_action
    from trezor.wire.errors import DataError

    from storage.cache_common import APP_ETH2_SIGNING_CONFIRMED
    from trezor.wire import context

    from apps.common.seed import get_seed, raise_if_not_initialized

    raise_if_not_initialized()

    if len(msg.signing_root) != 32:
        raise DataError("Signing root must be exactly 32 bytes")

    if not context.cache_get_bool(APP_ETH2_SIGNING_CONFIRMED):
        await confirm_action(
            "eth2_enable_validator_signing",
            "Enable validator signing?",
            description="Allow this session to sign consensus messages with "
            "the validator key m/12381/3600/{}/0/0.".format(
                msg.validator_index
            ),
        )
        context.cache_set_bool(APP_ETH2_SIGNING_CONFIRMED, True)

    # TODO: EIP-3076 slashing protection - check the (source, target) pair
    # against signer-core's SlashingDb and record it before signing. Wiring
    # the database to device storage is a later milestone.
    # TODO: when domain_type is provided, check it against the expected
    # beacon-chain domains as part of the EIP-3076 checks.
    # (msg.domain_type is currently unused.)

    import trezorbls

    seed = await get_seed()
    signature = trezorbls.sign(seed, msg.validator_index, msg.signing_root)
    return Eth2Signature(signature=signature)
