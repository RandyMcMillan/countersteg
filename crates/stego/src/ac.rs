//! Mixed-radix selection coder driving distribution-preserving selection —
//! MITIGATIONS.md M7.
//!
//! Role swap per generative-linguistic-steganography practice: the payload
//! chooser runs the DECODER over the framed payload integer (big-endian);
//! extraction runs the ENCODER over the replayed decisions and recovers the
//! payload integer exactly.
//!
//! Why mixed radix instead of a binary arithmetic coder: a binary AC with
//! E1/E2/E3 renormalization is NOT exactly invertible in the embed
//! direction — the E3 underflow case defers bits and re-emits them as
//! complements of the resolving bit, so `encode(decode(x)) != x` whenever
//! the stream's underflow-run bits disagree with that pattern (verified
//! empirically: the framing MAC failed on ~every short message). Mixed
//! radix over the choice arities is a pure bijection:
//!
//! ```text
//! embed:   x_0 = payload int;  query t:  s_t = x_t mod a_t;  x_{t+1} = x_t / a_t
//! extract: rebuild  for t = N-1 downto 0:  x_t = x_{t+1} * a_t + s_t   => x_0
//! ```
//!
//! with `a_t` the number of candidates at decision `t` and `s_t` the chosen
//! index. No carries, no renormalization, no approximation: the replay
//! reproduces the payload integer bit for bit. Decoding a (pseudo)random
//! integer yields `s_t` uniform over all `a_t` candidates (v2's n-bit
//! chunking was biased to `2^n` of `arity`), so a warden modeling the
//! engine's choice distribution sees no bias — that is the M8 test.
//!
//! Zero dependencies: a minimal little-endian-limb bignum with small
//! multiply/add/divmod is all the radix arithmetic needs.

/// Minimal bignum: little-endian `u64` limbs, sized for the payload
/// region (up to 298 bytes / ~2400 bits for a max-length message).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    /// Big-endian bytes -> integer. Empty input is zero.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let limbs = vec![0u64; bytes.len() / 8 + 1];
        let mut x = Self { limbs };
        for &b in bytes {
            x.mul_small(256);
            x.add_small(b as u32);
        }
        x.trim();
        x
    }

    /// Integer -> minimal big-endian bytes. Callers that need a stable
    /// top-of-stream layout must guarantee a nonzero sentinel byte at the
    /// very top of the payload (see `crate::SENTINEL`).
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.limbs.len() * 8);
        for &limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        // Strip leading zero bytes (minimal encoding).
        let first_nonzero = out.iter().position(|&b| b != 0).unwrap();
        out[first_nonzero..].to_vec()
    }

    /// x = x * m + a, with m, a < 2^32 (arity and symbol fit easily).
    pub fn mul_add_small(&mut self, m: u32, a: u32) {
        self.mul_small(m);
        self.add_small(a);
    }

    /// x = x * m.
    fn mul_small(&mut self, m: u32) {
        if m == 0 {
            self.limbs.clear();
            return;
        }
        if m == 1 {
            return;
        }
        let mut carry = 0u64;
        for limb in self.limbs.iter_mut() {
            let v = (*limb as u128) * (m as u128) + carry as u128;
            *limb = v as u64;
            carry = (v >> 64) as u64;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    /// x = x + a, a < 2^32.
    fn add_small(&mut self, a: u32) {
        let mut carry = a as u64;
        let mut i = 0;
        while carry != 0 {
            if i == self.limbs.len() {
                self.limbs.push(0);
            }
            let v = self.limbs[i] as u128 + carry as u128;
            self.limbs[i] = v as u64;
            carry = (v >> 64) as u64;
            i += 1;
        }
    }

    /// Returns x mod d, then x = x / d (truncating), for 1 <= d < 2^32.
    /// d == 1 leaves x unchanged and returns 0 (base-1 digit).
    pub fn divmod_small(&mut self, d: u32) -> u32 {
        debug_assert!(d >= 1);
        if d == 1 {
            return 0;
        }
        let mut rem = 0u64;
        for limb in self.limbs.iter_mut().rev() {
            let cur = ((rem as u128) << 64) | (*limb as u128);
            *limb = (cur / d as u128) as u64;
            rem = (cur % d as u128) as u64;
        }
        self.trim();
        rem as u32
    }

    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }
}

/// Decoder role: pops one mixed-radix digit per `decode` call, steering
/// generation. Digits of a pseudorandom (encrypted + MACed) integer are
/// uniform over the full radix at every position.
pub struct RadixDecoder {
    x: BigUint,
}

impl RadixDecoder {
    pub fn new(x: BigUint) -> Self {
        Self { x }
    }

    pub fn decode(&mut self, arity: u32) -> u32 {
        self.x.divmod_small(arity.max(1))
    }
}

/// Encoder role: re-encodes a replayed digit sequence back into the payload
/// integer. Callers must feed digits in REVERSE decision order (see module
/// docs): the last decision is the most significant digit.
pub struct RadixEncoder {
    x: BigUint,
}

impl RadixEncoder {
    pub fn new() -> Self {
        Self { x: BigUint { limbs: Vec::new() } }
    }

    pub fn encode(&mut self, digit: u32, arity: u32) {
        self.x.mul_add_small(arity.max(1), digit);
    }

    pub fn finish(self) -> BigUint {
        self.x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);
    impl Lcg {
        fn byte(&mut self) -> u8 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u8
        }
    }

    /// The extraction-side bijection: replaying popped digits through the
    /// encoder (reverse order) and re-decoding must reproduce the digit
    /// sequence exactly — decode(encode(S)) == S for any digit sequence.
    #[test]
    fn encode_decode_roundtrip_is_exact() {
        let mut lcg = Lcg(0xC0FFEE);
        for case in 0..50 {
            // Payload small enough that the arity product covers it —
            // the same relation production relies on. Top byte nonzero,
            // as the production sentinel guarantees.
            let mut payload: Vec<u8> = (0..6).map(|_| lcg.byte()).collect();
            payload[0] = 0x01;
            let arities: Vec<u32> = (0..(20 + case % 7))
                .map(|_| 1 + (lcg.byte() as u32 % 9)) // arities 1..=9
                .collect();

            let mut dec = RadixDecoder::new(BigUint::from_be_bytes(&payload));
            let mut digits = Vec::new();
            for &a in &arities {
                digits.push(dec.decode(a));
            }
            let mut enc = RadixEncoder::new();
            for (&d, &a) in digits.iter().zip(arities.iter()).rev() {
                enc.encode(d, a);
            }
            let rebuilt = enc.finish();

            // Re-decode the rebuilt integer: same digits, same order.
            let mut dec2 = RadixDecoder::new(rebuilt.clone());
            for (i, &a) in arities.iter().enumerate() {
                assert_eq!(dec2.decode(a), digits[i], "case {case} digit {i}");
            }

            // And with the payload below the product, the rebuild is the
            // payload itself, bit for bit.
            let prod = arities.iter().map(|&a| (a as u128)).product::<u128>();
            if payload.len() * 8 <= (127 - prod.leading_zeros()) as usize {
                assert_eq!(rebuilt.to_be_bytes(), payload, "case {case}");
            }
        }
    }

    /// Digits of a pseudorandom integer are uniform over the full radix —
    /// the distribution-preservation property M7 exists for.
    #[test]
    fn digits_are_uniform_over_full_arity() {
        let mut lcg = Lcg(42);
        let mut tally = vec![0u32; 8];
        let mut n = 0u32;
        // Fresh payload per batch: digits of one integer are sequential
        // (correlated), so sample many independent integers.
        for _ in 0..200 {
            let payload: Vec<u8> = (0..96).map(|_| lcg.byte()).collect();
            let mut dec = RadixDecoder::new(BigUint::from_be_bytes(&payload));
            for _ in 0..48 {
                let d = dec.decode(8);
                tally[d as usize] += 1;
                n += 1;
            }
        }
        let expect = n as f64 / 8.0;
        for (i, &t) in tally.iter().enumerate() {
            let dev = (t as f64 - expect).abs() / expect;
            assert!(dev < 0.1, "digit {i} deviates {dev:.3} from uniform");
        }
    }

    #[test]
    fn arity_one_always_yields_zero() {
        let payload = vec![0x01, 0x02, 0x03];
        let mut dec = RadixDecoder::new(BigUint::from_be_bytes(&payload));
        assert_eq!(dec.decode(1), 0);
        assert_eq!(dec.decode(1), 0);
    }

    #[test]
    fn bignum_mul_divmod_small() {
        let mut x = BigUint::from_be_bytes(&[0x01, 0x23, 0x45, 0x67, 0x89]);
        // (x * m + a) / m == x, rem a — mul_add then divmod undo each other.
        let orig = x.clone();
        x.mul_add_small(7, 3);
        let r = x.divmod_small(7);
        assert_eq!(r, 3);
        assert_eq!(x, orig);
    }
}
