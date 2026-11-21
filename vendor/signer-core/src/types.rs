//! The fixed-size consensus-specs containers whose signing roots this crate
//! computes. Field order matters: SSZ container roots merkleize the field
//! roots in declaration order.

use crate::ssz::{merkleize, HashTreeRoot};

/// A 48-byte compressed BLS12-381 public key, used as a per-validator key in
/// the slashing database.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey([u8; 48]);

impl PubKey {
    /// Wrap raw compressed bytes.
    pub const fn from_bytes(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    /// Raw compressed bytes.
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

impl core::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// `Fork` (consensus-specs): the schedule of fork versions. The signing
/// domain is derived from the fork version active at a given epoch — see
/// [`crate::domains::fork_version_at_epoch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    /// Fork version for epochs before `epoch`.
    pub previous_version: [u8; 4],
    /// Fork version for `epoch` onwards.
    pub current_version: [u8; 4],
    /// First epoch at which `current_version` applies.
    pub epoch: u64,
}

impl HashTreeRoot for Fork {
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            self.previous_version.hash_tree_root(),
            self.current_version.hash_tree_root(),
            self.epoch.hash_tree_root(),
        ])
    }
}

/// `ForkInfo` (Remote Signing API): a [`Fork`] plus the chain-identifying
/// `genesis_validators_root` that seeds every domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkInfo {
    /// The fork schedule context.
    pub fork: Fork,
    /// `state.genesis_validators_root`.
    pub genesis_validators_root: [u8; 32],
}

/// `Checkpoint`: an epoch and the block root finalized/justified at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Epoch of the checkpoint.
    pub epoch: u64,
    /// Root of the checkpoint's first block.
    pub root: [u8; 32],
}

impl HashTreeRoot for Checkpoint {
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[self.epoch.hash_tree_root(), self.root.hash_tree_root()])
    }
}

/// `AttestationData`: the object a validator signs for an attestation duty
/// (domain `DOMAIN_BEACON_ATTESTER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationData {
    /// Slot being attested to.
    pub slot: u64,
    /// Committee index.
    pub index: u64,
    /// Root of the block being voted for.
    pub beacon_block_root: [u8; 32],
    /// Justified checkpoint (source).
    pub source: Checkpoint,
    /// Checkpoint being finalized (target).
    pub target: Checkpoint,
}

impl HashTreeRoot for AttestationData {
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            self.slot.hash_tree_root(),
            self.index.hash_tree_root(),
            self.beacon_block_root.hash_tree_root(),
            self.source.hash_tree_root(),
            self.target.hash_tree_root(),
        ])
    }
}

/// `BeaconBlockHeader`: the object a proposer signs for block duties
/// (domain `DOMAIN_BEACON_PROPOSER`). Post-Bellatrix blocks are signed in
/// this header-only form; the header's `body_root` stands in for the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    /// Slot of the block.
    pub slot: u64,
    /// Validator index of the proposer.
    pub proposer_index: u64,
    /// Root of the parent block.
    pub parent_root: [u8; 32],
    /// Root of the post-state.
    pub state_root: [u8; 32],
    /// Root of the block body.
    pub body_root: [u8; 32],
}

impl HashTreeRoot for BeaconBlockHeader {
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            self.slot.hash_tree_root(),
            self.proposer_index.hash_tree_root(),
            self.parent_root.hash_tree_root(),
            self.state_root.hash_tree_root(),
            self.body_root.hash_tree_root(),
        ])
    }
}

/// `VoluntaryExit` (domain `DOMAIN_VOLUNTARY_EXIT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoluntaryExit {
    /// Earliest epoch at which the exit is valid.
    pub epoch: u64,
    /// Index of the exiting validator.
    pub validator_index: u64,
}

impl HashTreeRoot for VoluntaryExit {
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            self.epoch.hash_tree_root(),
            self.validator_index.hash_tree_root(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed, independently computed vectors. Expected values were produced
    // with a throwaway Python script (hashlib only) implementing the SSZ
    // merkleization rules directly from consensus-specs, without any Ethereum
    // library — see the crate tests in domains.rs for the matching domain
    // vectors.

    fn test_attestation_data() -> AttestationData {
        AttestationData {
            slot: 1101,
            index: 3,
            beacon_block_root: core::array::from_fn(|i| (i + 1) as u8),
            source: Checkpoint {
                epoch: 33,
                root: [0xaa; 32],
            },
            target: Checkpoint {
                epoch: 34,
                root: [0xbb; 32],
            },
        }
    }

    fn test_header() -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: 502874,
            proposer_index: 9001,
            parent_root: [0xcc; 32],
            state_root: [0xdd; 32],
            body_root: [0xee; 32],
        }
    }

    #[test]
    fn attestation_data_fixed_vector() {
        let expected: [u8; 32] = [
            0x29, 0x86, 0x5b, 0x7a, 0x23, 0xd7, 0x63, 0x55, 0x45, 0x0e, 0x40, 0x45, 0x74, 0x42,
            0xd3, 0x56, 0x1f, 0xe9, 0xca, 0x6f, 0x9a, 0x91, 0xee, 0xc6, 0xde, 0xa7, 0x1a, 0x33,
            0x88, 0x30, 0x62, 0x23,
        ];
        assert_eq!(test_attestation_data().hash_tree_root(), expected);
    }

    #[test]
    fn beacon_block_header_fixed_vector() {
        let expected: [u8; 32] = [
            0x92, 0xc4, 0xc6, 0x6e, 0x85, 0xc8, 0x76, 0xcf, 0x73, 0x10, 0x72, 0x02, 0x46, 0x40,
            0xc5, 0x9b, 0xae, 0xfb, 0x0b, 0xde, 0x2c, 0x3b, 0x90, 0x7a, 0x3d, 0xc7, 0x6d, 0xe5,
            0xe0, 0x10, 0xb6, 0xc7,
        ];
        assert_eq!(test_header().hash_tree_root(), expected);
    }

    #[test]
    fn voluntary_exit_fixed_vector() {
        let exit = VoluntaryExit {
            epoch: 194,
            validator_index: 12345,
        };
        let expected: [u8; 32] = [
            0xe2, 0x25, 0xee, 0x01, 0x69, 0xf1, 0x34, 0xd7, 0xd2, 0xbe, 0x9b, 0x33, 0xa6, 0x43,
            0xd7, 0x18, 0xe8, 0xea, 0x9c, 0x67, 0x86, 0x81, 0x87, 0x1f, 0x84, 0x59, 0x13, 0xb0,
            0x12, 0x2e, 0x53, 0x52,
        ];
        assert_eq!(exit.hash_tree_root(), expected);
    }

    #[test]
    fn fork_fixed_vector() {
        let fork = Fork {
            previous_version: [0, 0, 0, 1],
            current_version: [0, 0, 0, 2],
            epoch: 100,
        };
        let expected: [u8; 32] = [
            0xf3, 0x55, 0xa5, 0x59, 0x05, 0x38, 0x2c, 0x77, 0x96, 0x44, 0xef, 0x0d, 0xfd, 0xbd,
            0x25, 0x51, 0x06, 0x39, 0xeb, 0x10, 0x9b, 0x5e, 0xd7, 0x85, 0x2a, 0x6a, 0xa8, 0xc6,
            0x73, 0xc7, 0x08, 0x11,
        ];
        assert_eq!(fork.hash_tree_root(), expected);
    }

    #[test]
    fn pubkey_debug_is_hex() {
        let pk = PubKey::from_bytes(core::array::from_fn(|i| i as u8));
        assert_eq!(
            alloc::format!("{pk:?}"),
            concat!(
                "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "202122232425262728292a2b2c2d2e2f"
            )
        );
    }
}
