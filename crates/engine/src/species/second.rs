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
    pub decisions: Vec<Note>,
    pub decisions: Vec<Decision>,
}
