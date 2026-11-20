//! Shared cantus firmus generation — species-independent.
//!
//! Every species counterpoints against the same Markov cantus firmus walk:
//! start on tonic, end on tonic, diatonic random walk between with the
//! Fuxian leap-follow (post-leap step, opposite direction) preference.
//!
//! Two matched paths, as in every species module:
//! - forward: [`walk_cf`] records `len - 1` decisions through a [`Chooser`];
//! - decoder: [`cf_decisions`] replays candidate generation against fixed
//!   notes to recover the choice sequence.
//!
//! The stego selection channel depends on the two agreeing bit-for-bit.

use crate::composer::{Chooser, Decision};
use crate::species::{scale_notes_in_range, CF_HIGH, CF_LOW};
use crate::theory::Note;

/// Weighted Markov candidates for the next CF note (diatonic steps -4..=4,
/// excluding unisons, range-bounded). Sorted by midi pitch for determinism.
fn cf_candidates(prev: Note, prev_prev: Option<Note>) -> Vec<Note> {
    let mut cands: Vec<Note> = scale_notes_in_range(CF_LOW, CF_HIGH)
        .into_iter()
        .filter(|n| {
            let d = Note::diatonic_distance(prev, *n);
            (1..=4).contains(&d.abs()) && {
                // Fux: a leap must be followed by a step in the opposite direction.
                if let Some(pp) = prev_prev {
                    let prev_move = Note::diatonic_distance(pp, prev);
                    if prev_move.abs() >= 3 {
                        let this_move = d;
                        // stepwise and contrary to the leap
                        return this_move.abs() <= 2 && this_move.signum() == -prev_move.signum();
                    }
                }
                true
            }
        })
        .collect();
    cands.sort_by_key(|n| n.midi());
    cands.dedup();
    cands
}

/// Candidate notes for the cantus firmus at position `i`, given the notes
/// already fixed at positions `< i`. Mirrors the generation path exactly.
pub(crate) fn cf_step_candidates(cf_prefix: &[Note], i: usize, len: usize) -> Vec<Note> {
    let last = cf_prefix[cf_prefix.len() - 1];
    let prev_prev = if cf_prefix.len() >= 2 {
        Some(cf_prefix[cf_prefix.len() - 2])
    } else {
        None
    };
    let mut cands = cf_candidates(last, prev_prev);
    if cands.is_empty() {
        // Dead end at range edge: relax the leap-follow rule.
        cands = scale_notes_in_range(CF_LOW, CF_HIGH)
            .into_iter()
            .filter(|n| {
                let d = Note::diatonic_distance(last, *n);
                (1..=4).contains(&d.abs())
            })
            .collect();
        cands.sort_by_key(|n| n.midi());
        cands.dedup();
    }
    if i == len - 1 {
        // End on tonic.
        cands.retain(|n| *n == Note::new(0, 0));
        if cands.is_empty() {
            cands.push(Note::new(0, 0));
        }
    }
    cands
}

/// The CF note sounding immediately before position `i` (for motion rules).
pub(crate) fn cf_prev_of(cf: &[Note], i: usize) -> Note {
    if i == 0 { cf[0] } else { cf[i - 1] }
}

/// Forward path: walk the cantus firmus for `len` positions, recording one
/// decision per step after the initial tonic. Shared by every species.
pub(crate) fn walk_cf<C: Chooser>(len: usize, chooser: &mut C) -> (Vec<Note>, Vec<Decision>) {
    let mut cf: Vec<Note> = Vec::with_capacity(len);
    let mut decisions: Vec<Decision> = Vec::with_capacity(len.saturating_sub(1));

    // Start on tonic; random walk between; cf_step_candidates forces the
    // tonic ending at i == len - 1.
    cf.push(Note::new(0, 0)); // C4

    for i in 1..len {
        let cands = cf_step_candidates(&cf, i, len);
        let arity = cands.len() as u32;
        let choice = chooser.choose(arity).min(arity - 1);
        decisions.push(Decision { arity, choice });
        cf.push(cands[choice as usize]);
    }

    (cf, decisions)
}

/// Decoder path: recover the CF decision sequence of a fixed cantus firmus
/// by replaying candidate generation. Errors on any note outside the
/// candidate set (tampered or non-countersteg MIDI).
pub(crate) fn cf_decisions(cf: &[Note]) -> Result<Vec<Decision>, String> {
    if cf.len() < 4 {
        return Err("need at least 4 CF notes".into());
    }
    let len = cf.len();
    let mut decisions = Vec::with_capacity(len - 1);

    for i in 1..len {
        let cands = cf_step_candidates(&cf[..i], i, len);
        let choice = cands
            .iter()
            .position(|n| *n == cf[i])
            .ok_or_else(|| format!("cf note {i} not in candidate set"))?;
        decisions.push(Decision {
            arity: cands.len() as u32,
            choice: choice as u32,
        });
    }

    Ok(decisions)
}
