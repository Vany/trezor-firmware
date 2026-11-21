//! Signature domains, per consensus-specs `beacon-chain.md` (`get_domain`,
//! `compute_domain`, `compute_signing_root`) and the fork.md fork schedule.
//!
//! A domain is 4 bytes of `DomainType` followed by the first 28 bytes of the
//! `ForkData` root, binding every signature to the fork version and the
//! chain's `genesis_validators_root`.

use crate::ssz::{merkleize, HashTreeRoot};
use crate::types::Fork;

/// A 4-byte SSZ `DomainType`.
pub type DomainType = [u8; 4];

/// `DOMAIN_BEACON_PROPOSER` — block proposals (BLOCK/BLOCK_V2).
pub const DOMAIN_BEACON_PROPOSER: DomainType = [0x00, 0x00, 0x00, 0x00];
/// `DOMAIN_BEACON_ATTESTER` — attestations.
pub const DOMAIN_BEACON_ATTESTER: DomainType = [0x01, 0x00, 0x00, 0x00];
/// `DOMAIN_RANDAO` — RANDAO reveals (the signed object is the epoch uint64).
pub const DOMAIN_RANDAO: DomainType = [0x02, 0x00, 0x00, 0x00];
/// `DOMAIN_DEPOSIT` — deposit signatures (genesis fork version, zero root).
pub const DOMAIN_DEPOSIT: DomainType = [0x03, 0x00, 0x00, 0x00];
/// `DOMAIN_VOLUNTARY_EXIT` — voluntary exits.
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = [0x04, 0x00, 0x00, 0x00];
/// `DOMAIN_SELECTION_PROOF` — aggregation-slot selection proofs.
pub const DOMAIN_SELECTION_PROOF: DomainType = [0x05, 0x00, 0x00, 0x00];
/// `DOMAIN_AGGREGATE_AND_PROOF` — signed aggregates.
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = [0x06, 0x00, 0x00, 0x00];
/// `DOMAIN_SYNC_COMMITTEE` — sync committee messages.
pub const DOMAIN_SYNC_COMMITTEE: DomainType = [0x07, 0x00, 0x00, 0x00];
/// `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` — sync aggregator selection.
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = [0x08, 0x00, 0x00, 0x00];
/// `DOMAIN_CONTRIBUTION_AND_PROOF` — sync committee contributions.
pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = [0x09, 0x00, 0x00, 0x00];
/// `DOMAIN_APPLICATION_BUILDER` — validator registrations (out-of-protocol).
pub const DOMAIN_APPLICATION_BUILDER: DomainType = [0x01, 0x00, 0x00, 0x00];

/// The fork version active at `epoch` (consensus-specs `get_domain`):
/// `current_version` when `epoch >= fork.epoch`, else `previous_version`.
pub fn fork_version_at_epoch(fork: &Fork, epoch: u64) -> [u8; 4] {
    if epoch >= fork.epoch {
        fork.current_version
    } else {
        fork.previous_version
    }
}

/// `compute_domain`: `domain_type || fork_data_root[..28]`, where the fork
/// data root is `hash_tree_root(ForkData(current_version, genesis_validators_root))`.
pub fn compute_domain(
    domain_type: DomainType,
    fork_version: [u8; 4],
    genesis_validators_root: [u8; 32],
) -> [u8; 32] {
    let fork_data_root = merkleize(&[
        fork_version.hash_tree_root(),
        genesis_validators_root.hash_tree_root(),
    ]);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// Convenience wrapper: the domain for `domain_type` at `epoch` under the
/// fork schedule and genesis root described by `fork_info` (spec `get_domain`).
pub fn domain_at_epoch(
    fork_info: &crate::types::ForkInfo,
    domain_type: DomainType,
    epoch: u64,
) -> [u8; 32] {
    compute_domain(
        domain_type,
        fork_version_at_epoch(&fork_info.fork, epoch),
        fork_info.genesis_validators_root,
    )
}

/// `compute_signing_root`:
/// `hash_tree_root(SigningData(object_root, domain))` — the 32 bytes actually
/// handed to BLS.
pub fn compute_signing_root(object_root: [u8; 32], domain: [u8; 32]) -> [u8; 32] {
    merkleize(&[object_root.hash_tree_root(), domain.hash_tree_root()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AttestationData, BeaconBlockHeader, Checkpoint, ForkInfo};

    // Expected values computed independently with a throwaway Python script
    // (hashlib only) following consensus-specs; see also the fixed vectors in
    // types.rs, which use the same fixture data.

    fn fork_info() -> ForkInfo {
        ForkInfo {
            fork: Fork {
                previous_version: [0, 0, 0, 1],
                current_version: [0, 0, 0, 2],
                epoch: 100,
            },
            genesis_validators_root: [0x04; 32],
        }
    }

    fn attestation_data() -> AttestationData {
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

    fn header() -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: 502874,
            proposer_index: 9001,
            parent_root: [0xcc; 32],
            state_root: [0xdd; 32],
            body_root: [0xee; 32],
        }
    }

    #[test]
    fn fork_version_selection_follows_epoch() {
        let fork = fork_info().fork;
        assert_eq!(fork_version_at_epoch(&fork, 99), [0, 0, 0, 1]);
        assert_eq!(fork_version_at_epoch(&fork, 100), [0, 0, 0, 2]);
        assert_eq!(fork_version_at_epoch(&fork, u64::MAX), [0, 0, 0, 2]);
    }

    #[test]
    fn attester_domain_fixed_vector() {
        // Attestations pick the fork version at the target epoch (34 < 100,
        // so the previous fork version applies here).
        let expected = [
            0x01, 0x00, 0x00, 0x00, 0x2f, 0x70, 0x08, 0x29, 0x25, 0xf8, 0x7e, 0x50, 0x19, 0x27,
            0x36, 0x80, 0x22, 0xb8, 0xb0, 0xbe, 0xfa, 0x1d, 0xbb, 0xdf, 0x9c, 0x08, 0x48, 0xc4,
            0x1a, 0x7d, 0x5d, 0x04,
        ];
        assert_eq!(
            domain_at_epoch(
                &fork_info(),
                DOMAIN_BEACON_ATTESTER,
                attestation_data().target.epoch
            ),
            expected
        );
    }

    #[test]
    fn attestation_signing_root_fixed_vector() {
        let expected = [
            0x32, 0xc1, 0xdf, 0x99, 0x86, 0x89, 0x45, 0xcb, 0x0e, 0x3b, 0xd6, 0x2a, 0x06, 0xcb,
            0x21, 0x8c, 0xc1, 0x46, 0x16, 0xbc, 0x02, 0x2b, 0xfa, 0x9c, 0x77, 0x7f, 0x1e, 0x4f,
            0xc2, 0x3f, 0x28, 0x27,
        ];
        let domain = domain_at_epoch(
            &fork_info(),
            DOMAIN_BEACON_ATTESTER,
            attestation_data().target.epoch,
        );
        assert_eq!(
            compute_signing_root(attestation_data().hash_tree_root(), domain),
            expected
        );
    }

    #[test]
    fn proposer_domain_with_zero_genesis_matches_known_constant() {
        // The genesis-version / zero-root proposer domain begins with the
        // famous ForkData root f5a5fd42... (SHA-256 of 64 zero bytes), which
        // appears in deposit-data tooling across the ecosystem.
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, [0, 0, 0, 0], [0; 32]);
        assert_eq!(
            domain,
            [
                0x00, 0x00, 0x00, 0x00, 0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30, 0x27, 0x98,
                0xef, 0x6e, 0xd3, 0x09, 0x97, 0x9b, 0x43, 0x00, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8,
                0xea, 0x98, 0x31, 0xa9
            ]
        );
    }

    #[test]
    fn header_signing_root_fixed_vector() {
        let expected = [
            0x79, 0x40, 0x8d, 0x23, 0x3c, 0x51, 0x1c, 0xb0, 0xc7, 0x3c, 0x34, 0xb0, 0xcb, 0x37,
            0x33, 0x75, 0x7c, 0xca, 0x3f, 0xa6, 0x79, 0xfb, 0xad, 0x94, 0xc5, 0x80, 0x9b, 0x86,
            0xed, 0xe8, 0xb7, 0xc8,
        ];
        // Block domain picks the fork version at the block's epoch
        // (502874 / 32 = 15714 >= 100 -> current version).
        let domain = domain_at_epoch(&fork_info(), DOMAIN_BEACON_PROPOSER, header().slot / 32);
        assert_eq!(
            compute_signing_root(header().hash_tree_root(), domain),
            expected
        );
    }

    #[test]
    fn randao_signing_root_fixed_vector() {
        let expected = [
            0x00, 0x92, 0xbe, 0x3f, 0x23, 0xdf, 0xf1, 0xeb, 0xf9, 0x89, 0x41, 0x1a, 0xef, 0x3a,
            0x25, 0x65, 0xff, 0xcb, 0xb5, 0x0e, 0x45, 0xf8, 0xa3, 0xdd, 0x55, 0x4c, 0xdc, 0x28,
            0x29, 0xa0, 0x86, 0x23,
        ];
        // RANDAO signs the bare epoch (uint64) under DOMAIN_RANDAO.
        let domain = domain_at_epoch(&fork_info(), DOMAIN_RANDAO, 194);
        assert_eq!(
            compute_signing_root(194u64.hash_tree_root(), domain),
            expected
        );
    }
}
