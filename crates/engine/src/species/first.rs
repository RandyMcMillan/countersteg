//! First-species counterpoint: one whole note against each cantus firmus note.
//!
//! Every point where the generator has more than one rule-valid continuation is
//! a *decision point*: the caller supplies the choice (random for plain
//! composition, payload-derived for steganography). Decisions and their arity
//! are logged so the stego layer can recover the exact choice sequence.

use crate::composer::{Chooser, Decision};
use crate::species::cf::{cf_decisions, cf_prev_of, walk_cf};
use crate::species::{scale_notes_in_range, CP_HIGH, CP_LOW};
use crate::theory::{is_consonant, is_perfect, Note};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composition {
    /// Cantus firmus: one whole note per position.
    pub cf: Vec<Note>,
    /// First-species counterpoint: one whole note per position.
    pub cp: Vec<Note>,
    /// Decision points in generation order (CF walk first, then CP).
    pub decisions: Vec<Decision>,
}

/// First-species counterpoint candidates against `cf` at position `i`,
/// given the previous counterpoint note `prev_cp`. Cascading relaxations
/// guarantee a non-empty result.
fn cp_candidates(cf: Note, prev_cp: Option<Note>, pos: u32, len: u32) -> Vec<Note> {
    let all = scale_notes_in_range(CP_LOW, CP_HIGH);
    let cands: Vec<Note> = all
        .iter()
        .copied()
        .filter(|n| {
            let interval = Note::semitone_distance(cf, *n);
            is_consonant(interval) && interval.abs() <= 16
        })
        .collect();

    let finalize = |mut cands: Vec<Note>| {
        let mut v: Vec<Note> = cands.drain(..).collect();
        v.sort_by_key(|n| n.midi());
        v.dedup();
        v
    };

    // Pass 1: strict first-species rules.
    let strict: Vec<Note> = cands
        .iter()
        .copied()
        .filter(|n| cp_rule_ok(cf, *n, prev_cp, pos, len, true))
        .collect();
    let strict = finalize(strict);
    if !strict.is_empty() {
        return strict;
    }

    // Pass 2: relax penultimate-imperfect and leap preferences.
    let relaxed: Vec<Note> = cands
        .iter()
        .copied()
        .filter(|n| cp_rule_ok(cf, *n, prev_cp, pos, len, false))
        .collect();
    let relaxed = finalize(relaxed);
    if !relaxed.is_empty() {
        return relaxed;
    }

    finalize(cands)
}

/// Single-voice counterpoint constraints (start/end perfect, leap limits).
/// Motion rules needing the previous CF note are enforced in `compose_with`.
fn cp_rule_ok(cf: Note, cp: Note, prev_cp: Option<Note>, pos: u32, len: u32, strict: bool) -> bool {
    let interval = Note::semitone_distance(cf, cp);

    // Start and end on perfect consonances.
    if pos == 0 || pos == len - 1 {
        if !is_perfect(interval) {
            return false;
        }
    }

    if let Some(p) = prev_cp {
        let cp_motion = Note::semitone_distance(p, cp);
        // Leap limit: at most a perfect fourth (5 semitones) per note.
        let leap_cap = if strict { 5 } else { 9 };
        if cp_motion.abs() > leap_cap {
            return false;
        }
    }
    true
}

/// Candidate notes for the counterpoint at position `i`, given all CF notes
/// and the counterpoint notes at positions `< i`. Mirrors the generation
/// path exactly (single-voice rules + motion rules + boundary fallbacks).
fn cp_step_candidates(cf: &[Note], cp_prefix: &[Note], i: usize, len: usize) -> Vec<Note> {
    let cf_note = cf[i];
    let pos = i as u32;
    let len = len as u32;
    let prev_cp = cp_prefix.last().copied();
    let prev_interval = if i > 0 {
        Some(Note::semitone_distance(cf[i - 1], cp_prefix[i - 1]))
    } else {
        None
    };

    let mut cands = cp_candidates(cf_note, prev_cp, pos, len);

    // Motion rules that need the previous CF/CP pair.
    let is_boundary = i == 0 || i == len as usize - 1;
    cands.retain(|n| {
        let interval = Note::semitone_distance(cf_note, *n);
        // Start and end must be perfect consonances — hard constraint.
        if is_boundary && !is_perfect(interval) {
            return false;
        }
        if let (Some(pc), Some(pi)) = (prev_cp, prev_interval) {
            let cf_motion = Note::semitone_distance(cf_prev_of(cf, i), cf_note);
            let cp_motion = Note::semitone_distance(pc, *n);
            // No parallel perfect consonances.
            if is_perfect(pi) && is_perfect(interval) && pi.rem_euclid(12) == interval.rem_euclid(12) {
                return false;
            }
            // No hidden (direct) perfect consonance by similar motion with a leap.
            if is_perfect(interval)
                && cf_motion.signum() == cp_motion.signum()
                && cf_motion != 0
                && cp_motion.abs() > 2
            {
                return false;
            }
        }
        // Penultimate position: prefer imperfect consonance.
        if i == len as usize - 2 && is_perfect(interval) && len > 4 {
            return false;
        }
        true
    });

    if cands.is_empty()
        || (is_boundary && !cands.iter().any(|n| is_perfect(Note::semitone_distance(cf_note, *n))))
    {
        // Deterministic fallback: nearest consonant note (perfect at boundaries).
        let all: Vec<Note> = scale_notes_in_range(CP_LOW, CP_HIGH)
            .into_iter()
            .filter(|n| {
                let iv = Note::semitone_distance(cf_note, *n);
                is_consonant(iv) && (!is_boundary || is_perfect(iv))
            })
            .collect();
        let pick = all
            .iter()
            .min_by_key(|n| Note::semitone_distance(cf_note, **n).abs())
            .copied()
            .unwrap_or(Note::new(0, 1));
        cands = vec![pick];
    }

    cands.sort_by_key(|n| n.midi());
    cands.dedup();
    cands
}

/// Generate a note-against-note first-species composition.
///
/// `len` is the number of whole-note positions (>= 4 so start/penultimate/end
/// rules all apply). Every nondeterministic choice goes through `chooser`,
/// and each decision (arity + taken index) is recorded on the result.
pub fn compose_with<C: Chooser>(len: usize, chooser: &mut C) -> Composition {
    assert!(len >= 4, "need at least 4 positions for species rules");

    // --- Cantus firmus: shared walk (species-independent). ---
    let (cf, mut decisions) = walk_cf(len, chooser);

    // --- Counterpoint: note against note, rule-validated. ---
    let mut cp: Vec<Note> = Vec::with_capacity(len);
    for i in 0..len {
        let cands = cp_step_candidates(&cf, &cp, i, len);
        let arity = cands.len() as u32;
        let choice = chooser.choose(arity).min(arity - 1);
        decisions.push(Decision { arity, choice });
        cp.push(cands[choice as usize]);
    }

    Composition { cf, cp, decisions }
}

/// Recover the decision sequence of an existing composition by replaying
/// candidate generation against the fixed notes. This is the decoder side of
/// the selection channel: `choice` is the index of the taken note in the
/// deterministic candidate list at each step.
///
/// Returns Err if any note is not in the candidate set (tampered or
/// non-countersteg MIDI).
pub fn decisions_of(cf: &[Note], cp: &[Note]) -> Result<Vec<Decision>, String> {
    if cf.len() != cp.len() {
        return Err("need equal voice lengths".into());
    }
    let len = cf.len();
    let mut decisions = cf_decisions(cf)?;
    decisions.reserve(len);

    for i in 0..len {
        let cands = cp_step_candidates(cf, &cp[..i], i, len);
        let choice = cands
            .iter()
            .position(|n| *n == cp[i])
            .ok_or_else(|| format!("cp note {i} not in candidate set"))?;
        decisions.push(Decision {
            arity: cands.len() as u32,
            choice: choice as u32,
        });
    }

    Ok(decisions)
}

/// Plain composition from a seed.
pub fn compose(seed: u64, len: usize) -> Composition {
    let mut chooser = crate::composer::RandomChooser::new(seed);
    compose_with(len, &mut chooser)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composer::capacity_bits;
    use crate::theory::{is_consonant as consonant, is_perfect};

    fn interval_at(c: &Composition, i: usize) -> i16 {
        Note::semitone_distance(c.cf[i], c.cp[i])
    }

    #[test]
    fn all_intervals_consonant() {
        for seed in 0..50 {
            let c = compose(seed, 16);
            for i in 0..c.cf.len() {
                assert!(
                    consonant(interval_at(&c, i)),
                    "seed {seed} pos {i}: dissonant vertical interval"
                );
            }
        }
    }

    #[test]
    fn endpoints_perfect_penultimate_imperfect() {
        for seed in 0..50 {
            let c = compose(seed, 16);
            let n = c.cf.len();
            assert!(is_perfect(interval_at(&c, 0)), "start");
            assert!(is_perfect(interval_at(&c, n - 1)), "end");
            assert!(
                !is_perfect(interval_at(&c, n - 2)),
                "penultimate must be imperfect (seed {seed})"
            );
        }
    }

    #[test]
    fn no_parallel_perfects() {
        for seed in 0..50 {
            let c = compose(seed, 16);
            for i in 1..c.cf.len() {
                let a = interval_at(&c, i - 1);
                let b = interval_at(&c, i);
                if is_perfect(a)
                    && is_perfect(b)
                    && a.rem_euclid(12) == b.rem_euclid(12)
                {
                    let cf_m = Note::semitone_distance(c.cf[i - 1], c.cf[i]);
                    let cp_m = Note::semitone_distance(c.cp[i - 1], c.cp[i]);
                    assert!(
                        !(cf_m.signum() == cp_m.signum() && cf_m != 0),
                        "seed {seed} pos {i}: parallel perfect"
                    );
                }
            }
        }
    }

    #[test]
    fn deterministic_for_seed() {
        let a = compose(123, 16);
        let b = compose(123, 16);
        assert_eq!(a, b);
    }

    #[test]
    fn decisions_valid() {
        for seed in 0..20 {
            let c = compose(seed, 16);
            for d in &c.decisions {
                assert!(d.arity >= 1 && d.choice < d.arity);
            }
            // CF contributes len-1 decisions, CP contributes len.
            assert_eq!(c.decisions.len(), c.cf.len() - 1 + c.cp.len());
        }
    }

    #[test]
    fn capacity_positive() {
        for seed in 0..20 {
            let c = compose(seed, 32);
            assert!(capacity_bits(&c.decisions) > 0);
        }
    }
}
