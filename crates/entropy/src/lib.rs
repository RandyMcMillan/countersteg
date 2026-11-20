//! entropy: keystream PRNG, Shannon entropy, and stream health stats.
//! xoroshiro128++ ported from the Xoroshiro128PlusPlus.rs gist.

/// xoroshiro128++ — small, fast, dependency-free 64-bit PRNG.
pub struct Xoroshiro128PlusPlus {
    s0: u64,
    s1: u64,
}

impl Xoroshiro128PlusPlus {
    pub fn new(seed: u128) -> Self {
        let mut s = Self {
            s0: (seed >> 64) as u64,
            s1: seed as u64,
        };
        if s.s0 == 0 && s.s1 == 0 {
            s.s0 = 0x9E37_79B9_7F4A_7C15;
        }
        // Warm up: discard the first outputs (all-zero seed state fixup).
        let _ = s.next_u64();
        let _ = s.next_u64();
        s
    }

    pub fn from_seed_bytes(b: &[u8; 32]) -> Self {
        let mut hi = [0u8; 8];
        let mut lo = [0u8; 8];
        hi.copy_from_slice(&b[0..8]);
        lo.copy_from_slice(&b[8..16]);
        Self::new(((u64::from_le_bytes(hi) as u128) << 64) | u64::from_le_bytes(lo) as u128)
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let s0 = self.s0;
        let mut s1 = self.s1;
        let out = s0.wrapping_add(s1).rotate_left(17).wrapping_add(s0);
        s1 ^= s0;
        self.s0 = s0.rotate_left(49) ^ s1 ^ (s1 << 21);
        self.s1 = s1.rotate_left(28);
        out
    }

    pub fn next_byte(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
}

/// XOR a buffer with the keystream (memory_xor.rs gist pattern).
pub fn apply_keystream(data: &mut [u8], rng: &mut Xoroshiro128PlusPlus) {
    for b in data.iter_mut() {
        *b ^= rng.next_byte();
    }
}

/// Shannon entropy in bits per byte. 8.0 = uniform.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Byte-histogram chi-square-like uniformity score (0 = perfect uniformity).
pub fn uniformity_deviation(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystream_not_degenerate() {
        let mut r = Xoroshiro128PlusPlus::new(42);
        let bytes: Vec<u8> = (0..4096).map(|_| r.next_byte()).collect();
        let h = shannon_entropy(&bytes);
        assert!(h > 7.9, "keystream entropy {h}");
    }

    #[test]
    fn keystream_xor_is_involution() {
        let mut r1 = Xoroshiro128PlusPlus::new(7);
        let mut r2 = Xoroshiro128PlusPlus::new(7);
        let mut msg = b"the quick brown fox".to_vec();
        let orig = msg.clone();
        apply_keystream(&mut msg, &mut r1);
        assert_ne!(msg, orig);
        apply_keystream(&mut msg, &mut r2);
        assert_eq!(msg, orig);
    }

    #[test]
    fn deterministic() {
        let mut a = Xoroshiro128PlusPlus::new(1);
        let mut b = Xoroshiro128PlusPlus::new(1);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn uniform_deviation_low() {
        let mut r = Xoroshiro128PlusPlus::new(99);
        let bytes: Vec<u8> = (0..8192).map(|_| r.next_byte()).collect();
        assert!(uniformity_deviation(&bytes) < 500.0);
    }
}
