//! Cross-validation of the hand-rolled xoroshiro128++ against the `rand_xoshiro`
//! crate (reference transition function by Blackman & Vigna). Dev-dependencies
//! only — the library itself stays zero-dependency.
//!
//! Our seeding differs from the reference (direct 128-bit state load + zero
//! fixup + two discarded warmup rounds instead of splitmix64 expansion), so the
//! test replicates *our* documented seeding convention on the reference type
//! and then compares output streams step for step.

use entropy::Xoroshiro128PlusPlus;
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoroshiro128PlusPlus as Reference;

fn seeded_pair(state: u128) -> (Xoroshiro128PlusPlus, Reference) {
    let ours = Xoroshiro128PlusPlus::new(state);
    // replicate new(): s0 = high word, s1 = low word (both little-endian in the seed array)
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&((state >> 64) as u64).to_le_bytes());
    seed[8..].copy_from_slice(&(state as u64).to_le_bytes());
    let mut theirs = Reference::from_seed(seed);
    // our new() discards two warmup outputs
    let _ = theirs.next_u64();
    let _ = theirs.next_u64();
    (ours, theirs)
}

#[test]
fn stream_matches_rand_xoshiro_step_for_step() {
    for state in [
        1u128,
        42,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
        u128::MAX,
        0x9E37_79B9_7F4A_7C15,
    ] {
        let (mut ours, mut theirs) = seeded_pair(state);
        for step in 0..4096 {
            assert_eq!(
                ours.next_u64(),
                theirs.next_u64(),
                "diverged at state {state:#034x} step {step}"
            );
        }
    }
}

#[test]
fn keystream_seedpath_matches_reference() {
    // keys::keystream() route: 32-byte key -> first 16 bytes as state.
    // Reproduce keys::derive_key here without depending on keys (keep the
    // dev-dep surface minimal); the SHA-256 cross-check lives in keys' tests.
    let key: [u8; 32] = {
        // fixed arbitrary key material — determinism is all that matters
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        k
    };
    let mut hi = [0u8; 8];
    let mut lo = [0u8; 8];
    hi.copy_from_slice(&key[0..8]);
    lo.copy_from_slice(&key[8..16]);
    let state = ((u64::from_le_bytes(hi) as u128) << 64) | u64::from_le_bytes(lo) as u128;

    let mut ours = Xoroshiro128PlusPlus::from_seed_bytes(&key);
    let (_, mut theirs) = seeded_pair(state);
    for step in 0..2048 {
        assert_eq!(ours.next_u64(), theirs.next_u64(), "keystream path step {step}");
    }
}
