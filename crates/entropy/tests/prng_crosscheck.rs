//! Step-for-step cross-validation of the hand-rolled xoroshiro128++ against
//! the reference `rand_xoshiro` crate (Blackman & Vigna's implementation).
//!
//! Our seeding conventions differ from the reference crate on purpose:
//!   * `Xoroshiro128PlusPlus::new(u128)` splits the seed into state words
//!     directly and discards two warmup outputs.
//!   * `from_seed_bytes(&[u8; 32])` takes the first 16 bytes little-endian.
//! The reference `from_seed([u8; 16])` loads `s0 = LE(seed[0..8])`,
//! `s1 = LE(seed[8..16])`. So to compare streams we replicate OUR documented
//! state layout on the reference generator, then advance both in lockstep.
//! This validates the transition and output functions, which is the part that
//! must be bit-exact.

use countersteg_entropy::Xoroshiro128PlusPlus;
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoroshiro128PlusPlus as Reference;

type Ours = Xoroshiro128PlusPlus;

/// Build our generator and a reference generator holding the SAME internal
/// state, replicating `Xoroshiro128PlusPlus::new(seed)`'s documented layout.
fn seeded_pair(state: u128) -> (Ours, Reference) {
    let ours = Ours::new(state);
    // new(): s0 = high word, s1 = low word (both little-endian in the seed array)
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&((state >> 64) as u64).to_le_bytes());
    seed[8..].copy_from_slice(&(state as u64).to_le_bytes());
    let mut theirs = Reference::from_seed(seed);
    let _ = theirs.next_u64(); // our new() discards two warmup outputs
    let _ = theirs.next_u64();
    (ours, theirs)
}

#[test]
fn stream_matches_rand_xoshiro_step_for_step() {
    // A spread of seeds: small values, alternating patterns, all-ones, and the
    // golden-ratio constant used by our zero-state fixup.
    let seeds: [u128; 5] = [
        1,
        42,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
        u128::MAX,
        0x9E37_79B9_7F4A_7C15,
    ];
    const STEPS: usize = 4096;
    for seed in seeds {
        let (mut ours, mut theirs) = seeded_pair(seed);
        for step in 0..STEPS {
            assert_eq!(
                ours.next_u64(),
                theirs.next_u64(),
                "stream diverged at seed {seed:#034x}, step {step}"
            );
        }
    }
}

/// The keystream path (`from_seed_bytes`) must also match once the reference
/// generator is loaded with the same state words.
#[test]
fn keystream_seedpath_matches_reference() {
    // Deterministic synthetic 32-byte key material.
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let mut ours = Ours::from_seed_bytes(&key);
    let mut seed = [0u8; 16];
    seed.copy_from_slice(&key[..16]); // s0 = LE(key[0..8]), s1 = LE(key[8..16])
    let mut theirs = Reference::from_seed(seed);
    for step in 0..2048 {
        assert_eq!(
            ours.next_byte(),
            (theirs.next_u64() >> 32) as u8,
            "keystream diverged at step {step}"
        );
    }
}
