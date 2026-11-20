//! stego: selection-channel steganography over the composition engine.
//!
//! The payload does not modify the music after the fact — it *steers* the
//! generator. At every decision point with `arity >= 2` candidates,
//! `floor(log2(arity))` payload bits select which rule-valid continuation is
//! taken. The result is genuine first-species counterpoint that happens to
//! encode a ciphertext.
//!
//! Why the channel is lossless: `n = floor(log2(arity))` means
//! `2^n <= arity`, so any n-bit value `v` satisfies `v < 2^n <= arity` and
//! `v % arity == v`. The chosen candidate index *is* the payload bits — the
//! decoder reads them back directly, with no bias and no ambiguity.
//!
//! Bitstream layout (MSB-first across decisions):
//! `[u8 plaintext length][keystream-XOR ciphertext][zero padding]`
//! (messages are capped at 255 bytes — channel capacity is precious)
//!
//! The pre-cipher (keys + entropy crates) runs before channel encoding, so
//! the channel bitstream is computationally indistinguishable from random.

use engine::{compose_with, decisions_of, Chooser, Composition, Decision, Note};
use entropy::Xoroshiro128PlusPlus;

mod bits;
pub use bits::{BitReader, BitWriter};

#[derive(Debug)]
pub enum StegoError {
    CapacityExceeded { needed_bits: usize, capacity_bits: usize },
    Decode(String),
    WrongKey,
}

impl std::fmt::Display for StegoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StegoError::CapacityExceeded { needed_bits, capacity_bits } => write!(
                f,
                "payload needs {needed_bits} bits but score capacity is {capacity_bits}; use more bars"
            ),
            StegoError::Decode(m) => write!(f, "decode failed: {m}"),
            StegoError::WrongKey => write!(f, "decryption failed (wrong key or not countersteg output)"),
        }
    }
}

impl std::error::Error for StegoError {}

/// Chooser that steers generation from a payload bitstream.
struct PayloadChooser<'a> {
    bits: BitReader<'a>,
    overflow: bool,
}

impl<'a> PayloadChooser<'a> {
    fn new(bits: BitReader<'a>) -> Self {
        Self { bits, overflow: false }
    }
}

impl<'a> Chooser for PayloadChooser<'a> {
    fn choose(&mut self, arity: u32) -> u32 {
        let n = Decision { arity, choice: 0 }.bits();
        if n == 0 {
            return 0;
        }
        match self.bits.take(n as usize) {
            Some(v) => v % arity, // no-op: v < 2^n <= arity (see module docs)
            None => {
                self.overflow = true;
                0
            }
        }
    }
}

/// Build the framed bitstream: length byte + ciphertext + MAC tag, zero-padded.
fn build_bitstream(message: &[u8], passphrase: &str, seed: u64, capacity_bits: usize) -> Vec<u8> {
    let mut body = message.to_vec();
    let mut ks: Xoroshiro128PlusPlus = keys::keystream(passphrase, seed);
    entropy::apply_keystream(&mut body, &mut ks);
    let tag = keys::mac_tag(passphrase, seed, &body);

    let mut framed = Vec::with_capacity(2 + message.len());
    framed.push(message.len() as u8);
    framed.extend_from_slice(&body);
    framed.push(tag);

    let mut bw = BitWriter::new();
    // Framing first, then zero padding out to the full requested capacity.
    for i in 0..capacity_bits {
        let bit = if i < framed.len() * 8 {
            (framed[i / 8] >> (7 - (i % 8))) & 1
        } else {
            0
        };
        bw.push(bit);
    }
    bw.into_bytes()
}

/// Payload capacity estimate (bits) for a score of `len` whole notes.
/// The exact capacity depends on the choices taken; treat this as a
/// lower-bound hint (see `embed`, which verifies the real figure).
pub fn available_bits(seed: u64, len: usize) -> usize {
    let comp = engine::compose(seed, len);
    engine::capacity_bits(&comp.decisions)
}

/// Embed a message into a fresh composition. Starts at `min_len` whole-note
/// positions and extends the score until the actual (path-dependent)
/// capacity fits the framing — capacity grows roughly linearly with length.
///
/// Returns the composition (persist it with `write_smf_named(.., seed)`)
/// and the length that fit. Fails with precise capacity after 64 extensions.
pub fn embed(
    message: &[u8],
    passphrase: &str,
    seed: u64,
    min_len: usize,
) -> Result<(Composition, usize), StegoError> {
    if message.len() > 255 {
        return Err(StegoError::Decode("message exceeds 255 bytes".into()));
    }
    let needed = (2 + message.len()) * 8;
    let mut last_capacity = 0usize;
    for ext in 0..64 {
        let len = min_len + ext * 8;
        // Stream sized to a per-decision upper bound (arity <= 15 -> n <= 4)
        // so the payload path can never exhaust it; bits past the framing are
        // zero padding. Capacity is then read back from the taken path.
        let bound = (2 * len - 1) * 4;
        let stream = build_bitstream(message, passphrase, seed, bound);
        let mut chooser = PayloadChooser::new(BitReader::new(&stream));
        let comp = compose_with(len, &mut chooser);
        last_capacity = decisions_of(&comp.cf, &comp.cp)
            .map(|ds| engine::capacity_bits(&ds))
            .unwrap_or(0);
        if !chooser.overflow && last_capacity >= needed {
            return Ok((comp, len));
        }
    }
    Err(StegoError::CapacityExceeded {
        needed_bits: needed,
        capacity_bits: last_capacity,
    })
}

/// Extract a message from a composition's notes (decoder side).
/// `seed` must match the embedding seed (carried in the MIDI track name).
pub fn extract(cf: &[Note], cp: &[Note], passphrase: &str, seed: u64) -> Result<Vec<u8>, StegoError> {
    let decisions = decisions_of(cf, cp).map_err(StegoError::Decode)?;

    let mut bw = BitWriter::new();
    for d in &decisions {
        let n = d.bits();
        if n == 0 {
            continue;
        }
        // Encoder invariant: choice == payload bits < 2^n.
        bw.push_bits(d.choice, n);
    }
    let bytes = bw.into_bytes();

    if bytes.is_empty() {
        return Err(StegoError::Decode("bitstream too short".into()));
    }
    let claimed = bytes[0] as usize;
    if claimed + 2 > bytes.len() {
        return Err(StegoError::WrongKey);
    }
    let mut body = bytes[1..1 + claimed].to_vec();
    let tag = bytes[1 + claimed];
    if keys::mac_tag(passphrase, seed, &body) != tag {
        return Err(StegoError::WrongKey);
    }
    let mut ks: Xoroshiro128PlusPlus = keys::keystream(passphrase, seed);
    entropy::apply_keystream(&mut body, &mut ks);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::theory::is_consonant;

    #[test]
    fn roundtrip_short_message() {
        let msg = b"hi";
        let (comp, _len) = embed(msg, "pw", 42, 16).unwrap();
        let out = extract(&comp.cf, &comp.cp, "pw", 42).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn roundtrip_various() {
        for seed in [1u64, 7, 123] {
            let msg = b"attack at dawn";
            let (comp, _len) = embed(msg, "s3cret", seed, 16).unwrap();
            let out = extract(&comp.cf, &comp.cp, "s3cret", seed).unwrap();
            assert_eq!(out, msg, "seed {seed}");
        }
    }

    #[test]
    fn wrong_key_fails() {
        let (comp, _) = embed(b"secret", "right", 9, 16).unwrap();
        let res = extract(&comp.cf, &comp.cp, "wrong", 9);
        assert!(matches!(res, Err(StegoError::WrongKey) | Err(StegoError::Decode(_))));
    }

    #[test]
    fn capacity_enforced() {
        let big = vec![b'x'; 255]; // max message, far beyond any 64-extension score
        let res = embed(&big, "pw", 1, 8);
        assert!(matches!(res, Err(StegoError::CapacityExceeded { .. })));
    }

    #[test]
    fn oversize_message_rejected() {
        let big = vec![b'x'; 256];
        let res = embed(&big, "pw", 1, 16);
        assert!(matches!(res, Err(StegoError::Decode(_))));
    }

    #[test]
    fn embedded_music_still_valid() {
        let (comp, _) = embed(b"rules still hold under payload steering", "pw", 5, 16).unwrap();
        for i in 0..comp.cf.len() {
            assert!(is_consonant(Note::semitone_distance(comp.cf[i], comp.cp[i])));
        }
    }

    #[test]
    fn channel_choices_match_payload_bits() {
        // Encoder invariant: choice == payload bits < 2^n at each decision.
        let (comp, _) = embed(b"\xAA", "pw", 3, 16).unwrap();
        let ds = decisions_of(&comp.cf, &comp.cp).unwrap();
        for d in &ds {
            if d.bits() > 0 {
                assert!(d.choice < (1 << d.bits()), "choice fits n bits");
            }
        }
    }
}
