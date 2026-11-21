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

from __future__ import annotations

from typing import TYPE_CHECKING

from . import messages
from .tools import workflow

if TYPE_CHECKING:
    from .client import Session


@workflow()
def get_public_key(session: Session, validator_index: int) -> messages.Eth2PublicKey:
    """Get the BLS12-381 public key of the validator signing key at
    m/12381/3600/validator_index/0/0 (experimental)."""
    return session.call(
        messages.Eth2GetPublicKey(validator_index=validator_index),
        expect=messages.Eth2PublicKey,
    )


def sign_root(
    session: Session, validator_index: int, signing_root: bytes
) -> messages.Eth2Signature:
    """Sign a 32-byte consensus signing root with the validator signing key
    at m/12381/3600/validator_index/0/0 (experimental)."""
    return session.call(
        messages.Eth2SignRoot(
            validator_index=validator_index,
            signing_root=signing_root,
        ),
        expect=messages.Eth2Signature,
    )
