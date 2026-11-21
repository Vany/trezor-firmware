//! EIP-3076 slashing protection for the subset of rules a signer enforces
//! before signing (the interchange format itself — import/export of history —
//! is out of scope here).
//!
//! Rules implemented (EIP-3076 "Conditions", plus `is_slashable_attestation_data`
//! from consensus-specs):
//!
//! - **Blocks**: refuse `slot <= last signed slot` unless the signing root is
//!   identical (a repeat sign). Recording only the latest block is the
//!   EIP-3076 "minimal database" strategy: it subsumes refusing slots at or
//!   below the minimum recorded slot.
//! - **Attestations**:
//!   - refuse `source_epoch > target_epoch`;
//!   - refuse a **double vote**: same target epoch as a retained attestation
//!     with different data (`is_slashable_attestation_data`: same target and
//!     different signing root or source), allowing an identical re-sign
//!     (same source, target and signing root);
//!   - refuse **surround votes both ways**: strictly wider or strictly
//!     narrower than a retained attestation;
//!   - enforce the **low watermark** (conditions 4 and 5): refuse
//!     `source < watermark_source` and `target <= watermark_target`
//!     (identical re-signs excepted).
//!
//! # Bounded memory
//!
//! A hardware wallet cannot keep every attestation ever signed, so each key
//! retains only the `capacity` most recent attestations plus a low watermark.
//! The watermark starts as the minimum source/target over the retained
//! entries (exactly EIP-3076 conditions 4/5 for a complete database) and, on
//! every eviction, is raised to the component-wise maximum of the evicted
//! entry. Raising it to the evicted maximum (rather than the minimum) makes
//! the trimmed database *conservative*: any attestation that could double
//! vote, surround, or be surrounded by an evicted entry has
//! `source < watermark_source` or `target <= watermark_target` and is
//! refused. The cost is occasional false refusals (e.g. re-signing something
//! that was evicted) — failing closed is the correct trade-off on a device.

use alloc::collections::{BTreeMap, VecDeque};
use core::fmt;

use crate::types::PubKey;

/// Combine an optional retained minimum with an optional evicted maximum:
/// the stricter (larger) floor wins; absent when both are absent.
fn lift_max(retained_min: Option<u64>, evicted_max: Option<u64>) -> Option<u64> {
    match (retained_min, evicted_max) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Why a request was refused by slashing protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashingError {
    /// The attestation has `source_epoch > target_epoch`.
    SourceAboveTarget { source: u64, target: u64 },
    /// The block's slot is not strictly newer than the last signed block
    /// (and it is not an identical re-sign).
    BlockNotNewer { slot: u64, last_slot: u64 },
    /// Same target epoch as a previously signed attestation, different data
    /// (EIP-3076 double vote).
    DoubleVote { source: u64, target: u64 },
    /// The new attestation surrounds a previously signed one.
    SurroundsExisting { source: u64, target: u64 },
    /// The new attestation is surrounded by a previously signed one.
    SurroundedByExisting { source: u64, target: u64 },
    /// Source epoch is below the low watermark (EIP-3076 condition 4).
    SourceBelowWatermark { source: u64, watermark: u64 },
    /// Target epoch is at or below the low watermark (EIP-3076 condition 5).
    TargetBelowWatermark { target: u64, watermark: u64 },
}

impl fmt::Display for SlashingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceAboveTarget { source, target } => {
                write!(f, "attestation source epoch {source} is above target epoch {target}")
            }
            Self::BlockNotNewer { slot, last_slot } => write!(
                f,
                "block slot {slot} is not newer than the last signed slot {last_slot} \
                 (and is not an identical re-sign)"
            ),
            Self::DoubleVote { source, target } => write!(
                f,
                "double vote: target epoch {target} already signed with different data \
                 (source {source})"
            ),
            Self::SurroundsExisting { source, target } => write!(
                f,
                "surround vote: attestation ({source}, {target}) surrounds a signed attestation"
            ),
            Self::SurroundedByExisting { source, target } => write!(
                f,
                "surround vote: attestation ({source}, {target}) is surrounded by a signed attestation"
            ),
            Self::SourceBelowWatermark { source, watermark } => write!(
                f,
                "source epoch {source} is below the low watermark {watermark}"
            ),
            Self::TargetBelowWatermark { target, watermark } => write!(
                f,
                "target epoch {target} is at or below the low watermark {watermark}"
            ),
        }
    }
}

/// A per-key slashing-protection store. `check_and_record_*` must run (and
/// succeed) before the corresponding object is signed; a successful call
/// records the object so future conflicting requests are refused.
pub trait SlashingDb {
    /// EIP-3076 block rule: allow slots strictly newer than the last signed
    /// block, or an identical re-sign of it; refuse everything else.
    fn check_and_record_block(
        &mut self,
        pubkey: &PubKey,
        slot: u64,
        signing_root: [u8; 32],
    ) -> Result<(), SlashingError>;

    /// EIP-3076 attestation rules (double vote, surround both ways,
    /// source/target sanity, low watermark), as described on the module.
    fn check_and_record_attestation(
        &mut self,
        pubkey: &PubKey,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: [u8; 32],
    ) -> Result<(), SlashingError>;
}

/// Default number of retained attestations per key. Each entry is 48 bytes
/// (two epochs plus a signing root), so the default costs 12 KiB per key.
pub const DEFAULT_ATTESTATION_HISTORY: usize = 256;

/// Per-validator signing history.
#[derive(Debug, Default)]
struct ValidatorHistory {
    /// Latest signed block: (slot, signing_root). One entry is sufficient
    /// (EIP-3076 minimal strategy).
    last_block: Option<(u64, [u8; 32])>,
    /// Component-wise maximum (source, target) over *evicted* entries;
    /// `None` until the ring buffer has overflowed at least once.
    evicted_max: Option<(u64, u64)>,
    /// Most recent attestations: (source, target, signing root), oldest first.
    recent: VecDeque<(u64, u64, [u8; 32])>,
}

/// In-memory [`SlashingDb`] with bounded per-key history, suitable for a
/// device with little RAM.
pub struct InMemorySlashingDb {
    capacity: usize,
    validators: BTreeMap<PubKey, ValidatorHistory>,
}

impl InMemorySlashingDb {
    /// Create a database retaining `attestation_history_capacity`
    /// attestations per key before the low watermark starts rising.
    ///
    /// # Panics
    /// Panics if `attestation_history_capacity` is zero.
    pub fn new(attestation_history_capacity: usize) -> Self {
        assert!(
            attestation_history_capacity > 0,
            "history capacity must be non-zero"
        );
        Self {
            capacity: attestation_history_capacity,
            validators: BTreeMap::new(),
        }
    }

    /// Number of keys tracked.
    pub fn key_count(&self) -> usize {
        self.validators.len()
    }

    /// Effective (source, target) low watermark for a key: the component-wise
    /// maximum of the minimum retained epoch and the maximum evicted epoch,
    /// or `None` per component when there is no history at all. Every allowed
    /// attestation satisfies `source >= wm_source` and `target > wm_target`
    /// (identical re-signs excepted).
    fn watermark(entry: &ValidatorHistory) -> (Option<u64>, Option<u64>) {
        let min_source = entry.recent.iter().map(|&(s, _, _)| s).min();
        let min_target = entry.recent.iter().map(|&(_, t, _)| t).min();
        let evicted = entry.evicted_max;
        (
            lift_max(min_source, evicted.map(|e| e.0)),
            lift_max(min_target, evicted.map(|e| e.1)),
        )
    }
}

impl Default for InMemorySlashingDb {
    fn default() -> Self {
        Self::new(DEFAULT_ATTESTATION_HISTORY)
    }
}

impl SlashingDb for InMemorySlashingDb {
    fn check_and_record_block(
        &mut self,
        pubkey: &PubKey,
        slot: u64,
        signing_root: [u8; 32],
    ) -> Result<(), SlashingError> {
        let entry = self.validators.entry(*pubkey).or_default();
        if let Some((last_slot, last_root)) = entry.last_block {
            let identical = last_slot == slot && last_root == signing_root;
            if !identical && slot <= last_slot {
                return Err(SlashingError::BlockNotNewer { slot, last_slot });
            }
            if identical {
                return Ok(());
            }
        }
        entry.last_block = Some((slot, signing_root));
        Ok(())
    }

    fn check_and_record_attestation(
        &mut self,
        pubkey: &PubKey,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: [u8; 32],
    ) -> Result<(), SlashingError> {
        if source_epoch > target_epoch {
            return Err(SlashingError::SourceAboveTarget {
                source: source_epoch,
                target: target_epoch,
            });
        }
        let entry = self.validators.entry(*pubkey).or_default();

        // Identical re-sign of a retained attestation is always allowed
        // (EIP-3076 repeat signing) and needs no new record.
        if entry
            .recent
            .iter()
            .any(|&(s, t, r)| s == source_epoch && t == target_epoch && r == signing_root)
        {
            return Ok(());
        }

        // Low watermark (conditions 4 and 5, extended to cover evictions).
        let (wm_source, wm_target) = Self::watermark(entry);
        if let Some(wm) = wm_source {
            if source_epoch < wm {
                return Err(SlashingError::SourceBelowWatermark {
                    source: source_epoch,
                    watermark: wm,
                });
            }
        }
        if let Some(wm) = wm_target {
            if target_epoch <= wm {
                return Err(SlashingError::TargetBelowWatermark {
                    target: target_epoch,
                    watermark: wm,
                });
            }
        }

        // Double votes and surround votes against every retained attestation.
        for &(prev_source, prev_target, _) in &entry.recent {
            if prev_target == target_epoch {
                // Same target epoch, different data.
                return Err(SlashingError::DoubleVote {
                    source: source_epoch,
                    target: target_epoch,
                });
            }
            if source_epoch < prev_source && target_epoch > prev_target {
                return Err(SlashingError::SurroundsExisting {
                    source: source_epoch,
                    target: target_epoch,
                });
            }
            if source_epoch > prev_source && target_epoch < prev_target {
                return Err(SlashingError::SurroundedByExisting {
                    source: source_epoch,
                    target: target_epoch,
                });
            }
        }

        entry
            .recent
            .push_back((source_epoch, target_epoch, signing_root));
        if entry.recent.len() > self.capacity {
            let (evicted_source, evicted_target, _) =
                entry.recent.pop_front().expect("length checked");
            let max = entry
                .evicted_max
                .unwrap_or((evicted_source, evicted_target));
            entry.evicted_max = Some((max.0.max(evicted_source), max.1.max(evicted_target)));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PubKey {
        PubKey::from_bytes([byte; 48])
    }

    fn root(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn blocks_first_sign_is_allowed() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_block(&key(1), 100, root(1)).unwrap();
    }

    #[test]
    fn blocks_newer_slot_is_allowed_and_recorded() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_block(&key(1), 100, root(1)).unwrap();
        db.check_and_record_block(&key(1), 101, root(2)).unwrap();
        // Now the older slot is refused even with a fresh root.
        let err = db
            .check_and_record_block(&key(1), 100, root(3))
            .unwrap_err();
        assert_eq!(
            err,
            SlashingError::BlockNotNewer {
                slot: 100,
                last_slot: 101
            }
        );
    }

    #[test]
    fn blocks_identical_resign_is_allowed() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_block(&key(1), 100, root(1)).unwrap();
        db.check_and_record_block(&key(1), 100, root(1)).unwrap();
    }

    #[test]
    fn blocks_same_slot_different_root_is_refused() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_block(&key(1), 100, root(1)).unwrap();
        let err = db
            .check_and_record_block(&key(1), 100, root(2))
            .unwrap_err();
        assert_eq!(
            err,
            SlashingError::BlockNotNewer {
                slot: 100,
                last_slot: 100
            }
        );
    }

    #[test]
    fn blocks_older_slot_is_refused() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_block(&key(1), 100, root(1)).unwrap();
        assert_eq!(
            db.check_and_record_block(&key(1), 99, root(1)).unwrap_err(),
            SlashingError::BlockNotNewer {
                slot: 99,
                last_slot: 100
            }
        );
    }

    #[test]
    fn blocks_are_tracked_per_key() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_block(&key(1), 100, root(1)).unwrap();
        // A different key has no history.
        db.check_and_record_block(&key(2), 100, root(1)).unwrap();
        assert_eq!(db.key_count(), 2);
    }

    #[test]
    fn attestations_refuse_source_above_target() {
        let mut db = InMemorySlashingDb::default();
        assert_eq!(
            db.check_and_record_attestation(&key(1), 10, 9, root(1))
                .unwrap_err(),
            SlashingError::SourceAboveTarget {
                source: 10,
                target: 9
            }
        );
        // Not recorded: state unchanged.
        assert_eq!(db.key_count(), 0);
    }

    #[test]
    fn attestations_allow_target_and_source_advances() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_attestation(&key(1), 10, 11, root(1))
            .unwrap();
        // Same source, newer target.
        db.check_and_record_attestation(&key(1), 10, 12, root(2))
            .unwrap();
        // Newer source and target.
        db.check_and_record_attestation(&key(1), 11, 13, root(3))
            .unwrap();
    }

    #[test]
    fn attestations_identical_resign_is_allowed() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_attestation(&key(1), 10, 11, root(1))
            .unwrap();
        db.check_and_record_attestation(&key(1), 10, 11, root(1))
            .unwrap();
    }

    #[test]
    fn attestations_same_target_different_root_is_a_double_vote() {
        let mut db = InMemorySlashingDb::default();
        // (10, 11) first so the watermark floor does not preempt the scan.
        db.check_and_record_attestation(&key(1), 10, 11, root(1))
            .unwrap();
        db.check_and_record_attestation(&key(1), 10, 12, root(2))
            .unwrap();
        assert_eq!(
            db.check_and_record_attestation(&key(1), 10, 12, root(3))
                .unwrap_err(),
            SlashingError::DoubleVote {
                source: 10,
                target: 12
            }
        );
    }

    #[test]
    fn attestations_same_target_different_source_is_a_double_vote() {
        // is_slashable_attestation_data: same target epoch, different data.
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_attestation(&key(1), 10, 12, root(1))
            .unwrap();
        db.check_and_record_attestation(&key(1), 11, 13, root(2))
            .unwrap();
        assert_eq!(
            db.check_and_record_attestation(&key(1), 12, 13, root(3))
                .unwrap_err(),
            SlashingError::DoubleVote {
                source: 12,
                target: 13
            }
        );
    }

    #[test]
    fn attestations_refuse_surrounding_vote() {
        let mut db = InMemorySlashingDb::default();
        // (8, 9) keeps the source watermark low so the surround check fires.
        db.check_and_record_attestation(&key(1), 8, 9, root(1))
            .unwrap();
        db.check_and_record_attestation(&key(1), 10, 12, root(2))
            .unwrap();
        assert_eq!(
            db.check_and_record_attestation(&key(1), 9, 13, root(3))
                .unwrap_err(),
            SlashingError::SurroundsExisting {
                source: 9,
                target: 13
            }
        );
    }

    #[test]
    fn attestations_refuse_surrounded_vote() {
        let mut db = InMemorySlashingDb::default();
        // (10, 11) keeps the target watermark low so the surround check fires.
        db.check_and_record_attestation(&key(1), 10, 11, root(1))
            .unwrap();
        db.check_and_record_attestation(&key(1), 10, 15, root(2))
            .unwrap();
        assert_eq!(
            db.check_and_record_attestation(&key(1), 11, 14, root(3))
                .unwrap_err(),
            SlashingError::SurroundedByExisting {
                source: 11,
                target: 14
            }
        );
    }

    #[test]
    fn attestations_are_tracked_per_key() {
        let mut db = InMemorySlashingDb::default();
        db.check_and_record_attestation(&key(1), 10, 11, root(1))
            .unwrap();
        // Independent history for another key.
        db.check_and_record_attestation(&key(2), 10, 11, root(2))
            .unwrap();
    }

    #[test]
    fn attestations_watermark_rises_on_eviction() {
        let mut db = InMemorySlashingDb::new(2);
        db.check_and_record_attestation(&key(1), 10, 11, root(1))
            .unwrap();
        db.check_and_record_attestation(&key(1), 10, 12, root(2))
            .unwrap();
        // Overflows capacity: (10, 11) is evicted; watermark becomes
        // (min retained source 10, max(min retained target 12, evicted 11)).
        db.check_and_record_attestation(&key(1), 10, 13, root(3))
            .unwrap();

        // Identical re-sign of a retained attestation still allowed.
        db.check_and_record_attestation(&key(1), 10, 12, root(2))
            .unwrap();

        // Source below the watermark (EIP-3076 condition 4 after trimming).
        assert_eq!(
            db.check_and_record_attestation(&key(1), 9, 20, root(4))
                .unwrap_err(),
            SlashingError::SourceBelowWatermark {
                source: 9,
                watermark: 10
            }
        );
        // Target at/below the watermark (condition 5): the evicted (10, 11)
        // must stay un-signable.
        assert_eq!(
            db.check_and_record_attestation(&key(1), 10, 11, root(1))
                .unwrap_err(),
            SlashingError::TargetBelowWatermark {
                target: 11,
                watermark: 12
            }
        );
        // Fresh attestation above the watermark is allowed.
        db.check_and_record_attestation(&key(1), 10, 14, root(5))
            .unwrap();
    }

    #[test]
    fn attestations_watermark_is_conservative_after_out_of_order_eviction() {
        let mut db = InMemorySlashingDb::new(1);
        db.check_and_record_attestation(&key(1), 10, 20, root(1))
            .unwrap();
        db.check_and_record_attestation(&key(1), 12, 21, root(2))
            .unwrap();
        // (10, 20) evicted; retained minimum source is 12, so an 11-source
        // attestation is refused even though it conflicts with nothing: the
        // trimmed database fails closed.
        assert_eq!(
            db.check_and_record_attestation(&key(1), 11, 30, root(3))
                .unwrap_err(),
            SlashingError::SourceBelowWatermark {
                source: 11,
                watermark: 12
            }
        );
    }
}
