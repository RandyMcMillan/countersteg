//! SimpleRng: a splitmix64-style mixer used for reproducible composition walks.
//! Ported from the Markov-Counterpoint.rs gist (LCG structure replaced with a
//! higher-quality 64-bit mixer so long scores do not degenerate).

pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed ^ 0x9E37_79B9_7F4A_7C15 }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, n).
    pub fn below(&mut self, n: u32) -> u32 {
        (self.next_u64() % n as u64) as u32
    }

    /// f64 in [0.0, 1.0).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut a = SimpleRng::new(42);
        let mut b = SimpleRng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn below_bounds() {
        let mut r = SimpleRng::new(7);
        for _ in 0..10_000 {
            let v = r.below(7);
            assert!(v < 7);
        }
    }
}
