//! Counterpoint species (Fux, *Gradus ad Parnassum*).
//!
//! Each species module implements one note-against-note texture as a
//! matched pair of paths over the same deterministic candidate generation:
//!
//! - a forward path (`compose_with`) that walks a [`Chooser`] through every
//!   rule-valid continuation, recording each decision (arity + taken index);
//! - a decoder path (`decisions_of`) that replays candidate generation
//!   against fixed notes to recover the exact choice sequence.
//!
//! The stego selection channel depends on the two paths agreeing
//! bit-for-bit: any note outside the candidate set must fail decoding.
//!
//! - [`first`]: first species — one whole note against each cantus firmus
//!   note. Only consonances, perfect at the boundaries, imperfect at the
//!   penultimate position.

pub mod first;

use crate::theory::Note;

// Voice ranges in semitone_pos units (C4 = 0; MIDI = 60 + pos).
// Shared by all species until a higher species needs different bounds.
pub(crate) const CF_LOW: i16 = -12; // C3
pub(crate) const CF_HIGH: i16 = 7; // G4
pub(crate) const CP_LOW: i16 = 0; // C4
pub(crate) const CP_HIGH: i16 = 24; // C6

/// All C-major scale notes whose semitone position falls in `low..=high`,
/// ordered by octave then degree.
pub(crate) fn scale_notes_in_range(low: i16, high: i16) -> Vec<Note> {
    let mut v = Vec::new();
    for octave in -2..=3 {
        for degree in 0..7u8 {
            let n = Note::new(degree, octave);
            let pos = n.semitone_pos();
            if (low..=high).contains(&pos) {
                v.push(n);
            }
        }
    }
    v
}
