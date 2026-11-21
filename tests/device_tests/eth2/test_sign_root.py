# This file is part of the Trezor project.
#
# Copyright (C) SatoshiLabs and contributors
#
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

"""ETH2 validator signing over the wire protocol (experimental).

The device under test must be an emulator built with the experimental `bls`
feature (e.g. `xtask build firmware --emulator -m T3T1 -p test-live`).

The default test device is initialized with the standard "all all all ..."
mnemonic; the validator key is EIP-2333-derived from its seed at
m/12381/3600/index/0/0.

Signature verification uses py_ecc when available. Otherwise the expected
values below must be filled in (e.g. from signer-core's test binary) and the
test compares against them.
"""

import pytest

from trezorlib import eth2
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure

pytestmark = [pytest.mark.models("delizia")]

SIGNING_ROOT = bytes(range(32))

# Expected values for validator_index=0 (m/12381/3600/0/0/0) of the standard
# test mnemonic ("all" x 12, no passphrase), computed off-device by signer-core
# (github.com/Vany/signer-router, core/) and cross-checked with py_ecc.
EXPECTED_PUBKEY = bytes.fromhex(
    "91e1abd192b685fbddf4949a57bfde3230fabf327dbf9bc3418a71735816ef6f"
    "780f8c2471d6301d4d6306d1617405bd"
)
EXPECTED_SIGNATURE = bytes.fromhex(
    "95d30bd1f0b21390f6587fc8cefb69cf46a83748eb9eb74ecd13523f020a31b5"
    "5ebbbb21c3c8f2f08c9cb5f1601469b017a339cc0a35077c3d31ba87697607a1"
    "dc7168f08d6254b8e9e05439824312b78e47dfa84c654d93f17e23f0a257d084"
)

try:
    from py_ecc.bls import G2ProofOfPossession as bls
except ImportError:
    bls = None


def _maybe_skip_without_verification() -> None:
    if bls is None and not EXPECTED_SIGNATURE:
        pytest.skip(
            "py_ecc is not installed and no precomputed vector was provided: "
            "fill in EXPECTED_PUBKEY/EXPECTED_SIGNATURE or install py_ecc"
        )


def test_eth2_get_public_key(session: Session):
    pubkey = eth2.get_public_key(session, 0).pubkey
    assert len(pubkey) == 48

    # a different validator index derives a different key
    other_pubkey = eth2.get_public_key(session, 1).pubkey
    assert len(other_pubkey) == 48
    assert other_pubkey != pubkey

    assert pubkey == EXPECTED_PUBKEY


def test_eth2_sign_root(session: Session):
    _maybe_skip_without_verification()

    pubkey = eth2.get_public_key(session, 0).pubkey
    signature = eth2.sign_root(session, 0, SIGNING_ROOT).signature
    assert len(signature) == 96

    # Fixed vectors always; an independent verifier too when available.
    assert pubkey == EXPECTED_PUBKEY
    assert signature == EXPECTED_SIGNATURE
    if bls is not None:
        assert bls.Verify(pubkey, SIGNING_ROOT, signature), (
            "BLS signature does not verify"
        )


def test_eth2_second_sign_is_silent(session: Session):
    _maybe_skip_without_verification()

    signature1 = eth2.sign_root(session, 0, SIGNING_ROOT).signature

    def fail_on_button_request():
        # A ButtonRequest resumes this generator; no request must arrive for
        # the second sign of the session.
        yield
        raise AssertionError("Second sign should not ask for confirmation")

    with session.test_ctx as client:
        client.set_input_flow(fail_on_button_request)
        signature2 = eth2.sign_root(session, 0, SIGNING_ROOT).signature

    assert signature2 == signature1


def test_eth2_rejects_bad_signing_root_length(session: Session):
    with pytest.raises(TrezorFailure, match="32 bytes"):
        eth2.sign_root(session, 0, b"\x00" * 31)
    with pytest.raises(TrezorFailure, match="32 bytes"):
        eth2.sign_root(session, 0, b"\x00" * 33)
