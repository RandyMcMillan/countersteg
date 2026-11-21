//! Second-species counterpoint: two half notes against each cantus firmus
//! whole note.
//!
//! Rules as coded constraints (R#, per the second-species plan; `d(x, y)`
//! is semitone distance, positions are CF indices `0..len`, pair `(a, b)`
//! is the downbeat/upbeat at position `i`, `prev` is the last sounding CP
//! note before `a`):
//!
//! | # | Rule | Predicate |
//! |---|------|-----------|
//! | R1 | Downbeat consonance | `is_consonant(d(cf[i], a))` |
//! | R2 | Downbeat imperfect preference (mid-phrase) | species-1 penultimate-style filter; relaxation pass only |
//! | R3 | Upbeat consonant OR passing tone | `is_consonant(d(f, b))` OR legal passing tone (R4) |
//! | R4 | Passing tone definition | `b` dissonant with `f`, and `d(a, b)` is a diatonic step (`abs ∈ {1, 2}`) in the same direction as the approach (`d(prev, a)` also a step, `sign(d(prev, a)) == sign(d(a, b))`) |
//! | R5 | No dissonance at 0, len-1, len-2 | hard filter on both beats at those positions |
//! | R6 | Start/end perfect | `is_perfect(d(f, a))` at `i == 0` and `i == len-1` (whole note) |
//! | R7 | End tonic | guaranteed by the shared CF walk (CF ends on tonic; CP end perfect per R6) |
//! | R8 | Penultimate downbeat imperfect | `!is_perfect(d(f, a))` at `i == len-2`, `len > 4` |
//! | R9 | No parallel perfects | species-1 check verbatim, applied at every half-note step |
//! | R10 | No hidden perfect by similar motion + leap | species-1 check verbatim, every half-note step |
//! | R11 | Leap cap per half-note step | `abs(motion) <= 5` strict / `<= 9` relaxed |
//! | R12 | Cascading relaxation | strict (R2/R8 on) → relaxed (leap 9, R2/R8 off) → consonant-only → nearest-consonant singleton; arity ≥ 1 always |
//!
//! Dissonance policy: **passing tones only** (decision D1) — neighbors and
//! cambiata are excluded, keeping the replay surface minimal. At `i == 0`
//! no `prev` exists; R5 bans dissonance there.
//!
//! Downbeat candidates reuse
//! [`crate::species::first::cp_step_candidates`] verbatim on the flat
//! half-note prefix (previous *sounding* CP note = upbeat of `i - 1`).
//! Positions 0 and len-1 are single whole notes: the upbeat repeats the
//! downbeat (`(a, a)`), a forced arity-1 singleton carrying zero bits.
//!
//! Forced fallback steps (R12 singletons, e.g. when motion rules ban every
//! boundary-conformant candidate) carry no choice and may violate motion
//! preferences — the same contract as species 1, where the
//! nearest-consonant fallback also bypasses motion rules.
//!
//! Decision ordering matches every species: CF walk decisions first, then
//! CP decisions position-major, beat-minor (`a` then `b`). Two chooser
//! calls per interior position — `3*len - 1` decisions total. The stego
//! framing replays in exactly this order.

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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::composer::capacity_bits;
    use crate::species::first::{compose as compose1, decisions_of as decisions_of1};
    use crate::theory::is_perfect;

    /// CF note sounding against CP index k (downbeat and upbeat of position i
    /// both sound against cf[i]).
    fn cf_at(c: &Composition2, k: usize) -> Note {
        c.cf[k / 2]
    }

    #[test]
    fn downbeats_consonant() {
        for seed in 0..50 {
            let c = compose2(seed, 16);
            for i in 0..c.cf.len() {
                let iv = Note::semitone_distance(c.cf[i], c.cp[2 * i]);
                assert!(
                    crate::theory::is_consonant(iv),
                    "seed {seed} pos {i}: dissonant downbeat"
                );
            }
        }
    }

    #[test]
    fn upbeats_consonant_or_legal_passing() {
        for seed in 0..50 {
            let c = compose2(seed, 16);
            for i in 1..c.cf.len() - 1 {
                let f = c.cf[i];
                let a = c.cp[2 * i];
                let b = c.cp[2 * i + 1];
                let iv = Note::semitone_distance(f, b);
                if crate::theory::is_consonant(iv) {
                    continue;
                }
                // Dissonant upbeat must be a textbook passing tone:
                // prev_sound -> a -> b, diatonic steps, same direction.
                let prev = c.cp[2 * i - 1];
                let approach = Note::semitone_distance(prev, a);
                let step = Note::semitone_distance(a, b);
                assert!(
                    (1..=2).contains(&approach.abs()),
                    "seed {seed} pos {i}: passing tone after a leap (approach {approach})"
                );
                assert!(
                    (1..=2).contains(&step.abs()),
                    "seed {seed} pos {i}: passing tone not a diatonic step ({step})"
                );
                assert_eq!(
                    approach.signum(),
                    step.signum(),
                    "seed {seed} pos {i}: passing tone changes direction"
                );
            }
        }
    }

    #[test]
    fn no_dissonance_at_penultimate() {
        for seed in 0..50 {
            let c = compose2(seed, 16);
            let n = c.cf.len();
            for k in [2 * (n - 2), 2 * (n - 2) + 1] {
                let iv = Note::semitone_distance(cf_at(&c, k), c.cp[k]);
                assert!(
                    crate::theory::is_consonant(iv),
                    "seed {seed}: dissonance at penultimate beat {k}"
                );
            }
        }
    }

    #[test]
    fn boundaries_whole_notes_perfect() {
        for seed in 0..50 {
            let c = compose2(seed, 16);
            let n = c.cf.len();
            assert_eq!(c.cp[0], c.cp[1], "start must be a single whole note");
            assert_eq!(
                c.cp[2 * n - 2],
                c.cp[2 * n - 1],
                "end must be a single whole note"
            );
            assert!(is_perfect(Note::semitone_distance(c.cf[0], c.cp[0])), "start");
            assert!(is_perfect(Note::semitone_distance(c.cf[n - 1], c.cp[2 * n - 1])), "end");
        }
    }

    #[test]
    fn penultimate_downbeat_imperfect() {
        for seed in 0..50 {
            let c = compose2(seed, 16);
            let n = c.cf.len();
            let iv = Note::semitone_distance(c.cf[n - 2], c.cp[2 * (n - 2)]);
            assert!(
                !is_perfect(iv),
                "seed {seed}: penultimate downbeat must be imperfect"
            );
        }
    }

    #[test]
    fn no_parallel_perfects_half_grid() {
        for seed in 0..50 {
            let c = compose2(seed, 16);
            // CP decisions follow CF decisions in the decision vector; the
            // decision for beat k sits at index (len - 1) + k.
            let cp_base = c.cf.len() - 1;
            for k in 1..c.cp.len() {
                // Forced fallback steps (arity 1) carry no choice and may
                // violate motion preferences — same contract as species 1.
                if c.decisions[cp_base + k].arity == 1 {
                    continue;
                }
                let (prev_cf, cf) = if k % 2 == 0 {
                    (c.cf[k / 2 - 1], c.cf[k / 2]) // downbeat: CF moves
                } else {
                    (c.cf[k / 2], c.cf[k / 2]) // upbeat: CF sustains
                };
                let a = Note::semitone_distance(prev_cf, c.cp[k - 1]);
                let b = Note::semitone_distance(cf, c.cp[k]);
                if is_perfect(a) && is_perfect(b) && a.rem_euclid(12) == b.rem_euclid(12) {
                    let cf_m = Note::semitone_distance(prev_cf, cf);
                    let cp_m = Note::semitone_distance(c.cp[k - 1], c.cp[k]);
                    assert!(
                        !(cf_m.signum() == cp_m.signum() && cf_m != 0),
                        "seed {seed} cp[{k}]: parallel perfect"
                    );
                }
            }
        }
    }

    #[test]
    fn deterministic_for_seed() {
        let a = compose2(123, 16);
        let b = compose2(123, 16);
        assert_eq!(a, b);
    }

    #[test]
    fn decisions_valid() {
        for seed in 0..20 {
            let c = compose2(seed, 16);
            for d in &c.decisions {
                assert!(d.arity >= 1 && d.choice < d.arity);
            }
            // CF contributes len-1, CP contributes 2 per position.
            assert_eq!(c.decisions.len(), c.cf.len() - 1 + 2 * c.cp.len() / 2);
        }
    }

    #[test]
    fn replay_roundtrip() {
        for seed in 0..20 {
            let c = compose2(seed, 16);
            let ds = decisions_of2(&c.cf, &c.cp).unwrap();
            assert_eq!(ds, c.decisions, "seed {seed}: replay mismatch");
        }
    }

    #[test]
    fn capacity_gain_over_species1() {
        // Measured over seeds 0..50: ~1.47x at len 8/16, ~1.51x at len 32.
        // Below the naive 2x because boundary positions carry zero-bit
        // upbeats and upbeats have smaller candidate sets than downbeats.
        for len in [8, 16, 32] {
            let cap2: usize = (0..20)
                .map(|s| capacity_bits(&compose2(s, len).decisions))
                .sum();
            let cap1: usize = (0..20)
                .map(|s| capacity_bits(&compose1(s, len).decisions))
                .sum();
            assert!(
                cap2 * 5 > cap1 * 7,
                "len {len}: species-2 capacity {cap2} not > 1.4x species-1 {cap1}"
            );
        }
    }

    #[test]
    fn reject_wrong_shape() {
        let c = compose2(1, 8);
        assert!(decisions_of2(&c.cf, &c.cf).is_err());
        let c1 = compose1(1, 8);
        assert!(decisions_of2(&c1.cf, &c1.cp).is_err());
        // Sanity: species-1 decoder still accepts species-1 shapes.
        assert!(decisions_of1(&c1.cf, &c1.cp).is_ok());
    }
}
