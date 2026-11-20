//! Diatonic theory primitives: scale degrees, semitone mapping, consonance.

/// Semitone offsets of the C-major scale, indexed by diatonic degree (0..7).
pub const MAJOR_SCALE: [i8; 7] = [0, 2, 4, 5, 7, 9, 11];

/// A note in the C-major diatonic space: degree 0..6 plus octave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Note {
    pub degree: u8,
    pub octave: i8,
}

impl Note {
    pub fn new(degree: u8, octave: i8) -> Self {
        assert!(degree < 7);
        Self { degree, octave }
    }

    /// MIDI pitch number (C4 = 60).
    pub fn midi(&self) -> u8 {
        (60 + self.octave * 12 + MAJOR_SCALE[self.degree as usize] as i8) as u8
    }

    /// Absolute semitone position relative to C4.
    pub fn semitone_pos(&self) -> i16 {
        (self.octave as i16) * 12 + MAJOR_SCALE[self.degree as usize] as i16
    }

    /// Inverse of `midi()`: maps a MIDI pitch in the C-major diatonic set
    /// back to a note. Returns None for chromatic pitches.
    pub fn from_midi(midi: u8) -> Option<Note> {
        let pos = midi as i16 - 60;
        let octave = pos.div_euclid(12) as i8;
        let offset = pos.rem_euclid(12) as i8;
        MAJOR_SCALE
            .iter()
            .position(|&s| s == offset)
            .map(|degree| Note::new(degree as u8, octave))
    }

    /// Diatonic steps between self and other (signed), used for leap rules.
    pub fn diatonic_distance(a: Note, b: Note) -> i8 {
        let ai = a.octave * 7 + a.degree as i8;
        let bi = b.octave * 7 + b.degree as i8;
        bi - ai
    }

    /// Semitone distance from a to b (signed).
    pub fn semitone_distance(a: Note, b: Note) -> i16 {
        b.semitone_pos() - a.semitone_pos()
    }
}

/// Semitone interval classes considered consonant (unison, m/M 3rd, P5, m/M 6th).
pub const CONSONANT_CLASSES: [i16; 6] = [0, 3, 4, 7, 8, 9];

/// Is the simple interval (octaves of a consonance are consonant) consonant?
pub fn is_consonant(semitones: i16) -> bool {
    let cls = semitones.rem_euclid(12);
    if cls == 0 {
        return true; // unison or octave(s)
    }
    CONSONANT_CLASSES[1..].contains(&cls)
}

/// Is the interval a *perfect* consonance (unison / fifth / octave)?
pub fn is_perfect(semitones: i16) -> bool {
    matches!(semitones.rem_euclid(12), 0 | 7)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consonance_table() {
        for semis in [0, 12, 19, 24] {
            assert!(is_consonant(semis), "perfect interval {semis}");
        }
        for semis in [3, 4, 8, 9, 15, 16] {
            assert!(is_consonant(semis), "imperfect consonance {semis}");
        }
        for semis in [1, 2, 6, 10, 11, 13] {
            assert!(!is_consonant(semis), "dissonance {semis}");
        }
        assert!(is_perfect(7) && is_perfect(19) && !is_perfect(3));
    }
}
