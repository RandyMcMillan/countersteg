//! engine: Markov-counterpoint hybrid composition engine.
//!
//! Combines a weighted Markov random walk (cantus firmus) with Fuxian
//! first-species counterpoint rules. All nondeterminism flows through the
//! [`Chooser`] trait so the stego crate can steer generation bit-by-bit.

pub mod composer;
pub mod midi;
pub mod rng;
pub mod species;
pub mod theory;

pub use composer::{
    capacity_bits, Chooser, Decision, RandomChooser, ReplayChooser, BEATS_PER_NOTE,
    TICKS_PER_BEAT, TICKS_PER_NOTE,
};
pub use species::first::{compose, compose_with, decisions_of, Composition};
pub use midi::{read_smf, write_smf, write_smf_named, NoteEvent, SmfData};
pub use theory::Note;
