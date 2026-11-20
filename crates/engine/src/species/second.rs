//! Second-species counterpoint: two half notes against each cantus firmus
//! whole note.
//!
//! Rules (textbook Fux, dissonance policy: passing tones only):
//! - downbeat: consonant with the CF — identical rule set to first species
//!   given the previous *sounding* CP note (the upbeat of position `i - 1`),
//!   so downbeat candidates reuse [`crate::species::first::cp_step_candidates`]
//!   verbatim on the flat half-note prefix;
//! - upbeat: consonant, or a dissonant passing tone — dissonance only between
//!   two diatonic steps in the same direction (`prev_sound → a → b` all
//!   stepwise, same sign), never at positions 0, len-1, or len-2;
//! - positions 0 and len-1 are single whole notes: the upbeat repeats the
//!   downbeat (`(a, a)`), carrying zero bits (singleton candidate list).
//!
//! Forced fallback steps (arity-1 candidate lists, e.g. when motion rules
//! ban every boundary-conformant candidate) carry no choice and may violate
//! motion preferences — the same contract as species 1, where the
//! nearest-consonant fallback also bypasses motion rules.
//!
//! Decision ordering matches every species: CF walk decisions first, then CP
//! decisions position-major, beat-minor (`a` then `b`). Two chooser calls per
//! position — `3*len - 1` decisions total.

use crate::composer::{Chooser, Decision};
use crate::species::cf::{cf_decisions, walk_cf};
use crate::species::first::cp_step_candidates;
use crate::species::{scale_notes_in_range, CP_HIGH, CP_LOW};
use crate::theory::{is_consonant, Note};

/// Semitone sizes of a diatonic step (whole or half step).
const STEP_MIN: i16 = 1;
const STEP_MAX: i16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composition2 {
    /// Cantus firmus: one whole note per position.
    pub cf: Vec<Note>,
    /// Counterpoint: two half notes per position (`2 * cf.len()` entries).
    /// Boundary positions repeat the note — a single sounding whole note.
    pub cp: Vec<Note>,
    /// Decision points in generation order (CF walk first, then CP:
    /// position-major, beat-minor).
    pub decisions: Vec<Decision>,
}

/// Upbeat candidates against CF note `f`, given the chosen downbeat `a` and
/// the previously sounding CP note `prev_sound` (None at position 0).
/// Cascading relaxations guarantee a non-empty result.
fn cp2_upbeat_candidates(
    f: Note,
    a: Note,
    prev_sound: Option<Note>,
    i: usize,
    len: usize,
) -> Vec<Note> {
    // Boundary positions are whole notes: the upbeat is the downbeat itself.
    if i == 0 || i == len - 1 {
        return vec![a];
    }
    // Dissonance ban at the penultimate position (both beats consonant).
    let allow_dissonance = i != len - 2;
    let approach = prev_sound.map(|p| Note::semitone_distance(p, a));

    let candidates_with_cap = |cap: i16| -> Vec<Note> {
        let mut cands: Vec<Note> = scale_notes_in_range(CP_LOW, CP_HIGH)
            .into_iter()
            .filter(|n| {
                let iv = Note::semitone_distance(f, *n);
                let step = Note::semitone_distance(a, *n);
                if is_consonant(iv) {
                    return step.abs() <= cap;
                }
                if !allow_dissonance {
                    return false;
                }
                // Passing tone: dissonant, and both surrounding motions are
                // diatonic steps in the same direction.
                if !(STEP_MIN..=STEP_MAX).contains(&step.abs()) {
                    return false;
                }
                match approach {
                    Some(x) if (STEP_MIN..=STEP_MAX).contains(&x.abs()) => {
                        x.signum() == step.signum()
                    }
                    _ => false,
                }
            })
            .collect();
        cands.sort_by_key(|n| n.midi());
        cands.dedup();
        cands
    };

    // Pass 1: strict (leap cap P4). Pass 2: relaxed (leap cap 9).
    // Pass 3: any consonance regardless of leap.
    for cap in [5i16, 9, i16::MAX] {
        let cands = candidates_with_cap(cap);
        if !cands.is_empty() {
            return cands;
        }
    }

    // Deterministic fallback: nearest consonant note to the downbeat.
    let all: Vec<Note> = scale_notes_in_range(CP_LOW, CP_HIGH)
        .into_iter()
        .filter(|n| is_consonant(Note::semitone_distance(f, *n)))
        .collect();
    let pick = all
        .iter()
        .min_by_key(|n| Note::semitone_distance(a, **n).abs())
        .copied()
        .unwrap_or(a);
    vec![pick]
}

/// Generate a second-species composition: two half notes per CF whole note.
///
/// `len` is the number of CF positions (>= 4). Every nondeterministic choice
/// goes through `chooser` — two calls per position, downbeat then upbeat —
/// and each decision (arity + taken index) is recorded on the result.
pub fn compose_with2<C: Chooser>(len: usize, chooser: &mut C) -> Composition2 {
    assert!(len >= 4, "need at least 4 positions for species rules");

    // --- Cantus firmus: shared walk (species-independent). ---
    let (cf, mut decisions) = walk_cf(len, chooser);

    // --- Counterpoint: half note against half note, rule-validated. ---
    let mut cp: Vec<Note> = Vec::with_capacity(2 * len);
    for i in 0..len {
        // Downbeat: same rule set as first species given the previous
        // sounding note (cp_prefix.last() = upbeat of position i - 1).
        let down = cp_step_candidates(&cf, &cp, i, len);
        let arity = down.len() as u32;
        let choice = chooser.choose(arity).min(arity - 1);
        decisions.push(Decision { arity, choice });
        let a = down[choice as usize];

        // Upbeat: consonant or legal passing tone, given the chosen downbeat.
        let prev_sound = if i == 0 { None } else { Some(cp[2 * i - 1]) };
        let up = cp2_upbeat_candidates(cf[i], a, prev_sound, i, len);
        let arity = up.len() as u32;
        let choice = chooser.choose(arity).min(arity - 1);
        decisions.push(Decision { arity, choice });
        let b = up[choice as usize];

        cp.push(a);
        cp.push(b);
    }

    Composition2 { cf, cp, decisions }
}

/// Recover the decision sequence of an existing second-species composition
/// by replaying candidate generation against the fixed notes. Decoder side
/// of the selection channel; errors on any note outside the candidate set.
pub fn decisions_of2(cf: &[Note], cp: &[Note]) -> Result<Vec<Decision>, String> {
    if cp.len() != 2 * cf.len() {
        return Err("need cp.len() == 2 * cf.len()".into());
    }
    let len = cf.len();
    let mut decisions = cf_decisions(cf)?;
    decisions.reserve(2 * len);

    for i in 0..len {
        let down = cp_step_candidates(cf, &cp[..2 * i], i, len);
        let choice = down
            .iter()
            .position(|n| *n == cp[2 * i])
            .ok_or_else(|| format!("cp downbeat {i} not in candidate set"))?;
        decisions.push(Decision {
            arity: down.len() as u32,
            choice: choice as u32,
        });

        let a = cp[2 * i];
        let prev_sound = if i == 0 { None } else { Some(cp[2 * i - 1]) };
        let up = cp2_upbeat_candidates(cf[i], a, prev_sound, i, len);
        let choice = up
            .iter()
            .position(|n| *n == cp[2 * i + 1])
            .ok_or_else(|| format!("cp upbeat {i} not in candidate set"))?;
        decisions.push(Decision {
            arity: up.len() as u32,
            choice: choice as u32,
        });
    }

    Ok(decisions)
}

/// Plain composition from a seed.
pub fn compose2(seed: u64, len: usize) -> Composition2 {
    let mut chooser = crate::composer::RandomChooser::new(seed);
    compose_with2(len, &mut chooser)
}
