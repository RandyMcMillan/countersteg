//! Decision infrastructure shared by all composition paths.
//!
//! Every point where a generator has more than one rule-valid continuation is
//! a *decision point*: the caller supplies the choice (random for plain
//! composition, payload-derived for steganography). Decisions and their arity
//! are logged so the stego layer can recover the exact choice sequence.
//!
//! Species-specific rules live in [`crate::species`].

use crate::rng::SimpleRng;

pub const BEATS_PER_NOTE: u32 = 4;
pub const TICKS_PER_BEAT: u32 = 480;
pub const TICKS_PER_NOTE: u32 = BEATS_PER_NOTE * TICKS_PER_BEAT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Number of rule-valid candidates at this point (>= 1).
    pub arity: u32,
    /// The candidate index that was taken (< arity).
    pub choice: u32,
}

impl Decision {
    /// floor(log2(arity)) — number of payload bits encodable here (0 if arity < 2).
    pub fn bits(&self) -> u32 {
        if self.arity < 2 {
            0
        } else {
            31 - self.arity.leading_zeros()
        }
    }
}

/// Pluggable decision maker. `arity` is the number of candidates (sorted
/// deterministically); the returned index must be < arity.
pub trait Chooser {
    fn choose(&mut self, arity: u32) -> u32;
}

/// Random chooser for plain composition.
pub struct RandomChooser {
    rng: SimpleRng,
}

impl RandomChooser {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: SimpleRng::new(seed),
        }
    }
}

impl Chooser for RandomChooser {
    fn choose(&mut self, arity: u32) -> u32 {
        if arity <= 1 {
            0
        } else {
            self.rng.below(arity)
        }
    }
}

/// Chooser that replays a pre-recorded choice sequence (stego decoder).
pub struct ReplayChooser<'a> {
    choices: &'a [u32],
    idx: usize,
}

impl<'a> ReplayChooser<'a> {
    pub fn new(choices: &'a [u32]) -> Self {
        Self { choices, idx: 0 }
    }

    pub fn consumed(&self) -> usize {
        self.idx
    }
}

impl<'a> Chooser for ReplayChooser<'a> {
    fn choose(&mut self, arity: u32) -> u32 {
        let c = self.choices.get(self.idx).copied().unwrap_or(0);
        self.idx += 1;
        c.min(arity.saturating_sub(1))
    }
}

/// Total payload capacity (bits) of a decision sequence.
pub fn capacity_bits(decisions: &[Decision]) -> usize {
    decisions.iter().map(|d| d.bits() as usize).sum()
}
