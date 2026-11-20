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
//! Bitstream layout (MSB-first across decisions), framing v2:
//! `[nonce le64][u8 plaintext length][keystream-XOR ciphertext][16-byte MAC tag]`
//! (messages are capped at 255 bytes — channel capacity is precious).
//!
//! Once the framing bits are consumed, generation falls back to a PRNG
//! chooser for all remaining decisions, so the tail of an embedded score is
//! distributed exactly like a natural composition (no candidate-0 padding
//! signature; see MITIGATIONS.md M4).
//!
//! The nonce is not secret and not metadata: it travels inside the framing
//! and keys the pre-cipher, so reusing a passphrase across messages never
//! reuses a keystream (MITIGATIONS.md M1). Nothing about the file identifies
//! it as countersteg output — the seed the *Compose* path publishes is a
//! public demo convenience and never appears in embedded files.
//!
//! The pre-cipher (keys crate, v2 schedule) runs before channel encoding, so
//! the channel bitstream is computationally indistinguishable from random.

use engine::{compose_with, decisions_of, Chooser, Composition, Decision, Note, RandomChooser};

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

/// Chooser that steers generation from the framed bitstream, then falls back
/// to a natural PRNG chooser once the framing is consumed. The fallback
/// keeps the score's tail distributionally identical to plain composition
/// (the old zero-padding design picked candidate 0 at every tail decision —
/// a glaring statistical signature; see MITIGATIONS.md A3/M4).
///
/// Capacity subtlety: a path "fits" only if the framing ends exactly on a
/// decision boundary. A decision whose n bits straddle the end of the
/// stream (some bits remain, but fewer than n) is flagged — extending the
/// score changes the path, so a later extension may align.
struct PayloadChooser<'a> {
    bits: BitReader<'a>,
    fallback: RandomChooser,
    straddled: bool,
}

impl<'a> PayloadChooser<'a> {
    fn new(bits: BitReader<'a>, fallback_seed: u64) -> Self {
        Self {
            bits,
            fallback: RandomChooser::new(fallback_seed),
            straddled: false,
        }
    }

    /// Framing bits eaten so far; equals the score's payload capacity used.
    fn consumed_bits(&self) -> usize {
        self.bits.consumed()
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
                if self.bits.remaining() > 0 {
                    // The framing's tail bits (fewer than n) cannot be
                    // encoded by this decision — the path is too short.
                    self.straddled = true;
                }
                self.fallback.choose(arity)
            }
        }
    }
}

/// Framing v2: nonce(8) || length(1) || ciphertext(len) || MAC tag(16).
pub const NONCE_BYTES: usize = 8;
pub const LEN_BYTES: usize = 1;
pub const TAG_BYTES: usize = 16;

/// Framing overhead in bits for a message of `msg_len` bytes.
pub fn framing_bits(msg_len: usize) -> usize {
    (NONCE_BYTES + LEN_BYTES + TAG_BYTES + msg_len) * 8
}

/// Build the framed bitstream (exactly `framing_bits` bytes — no padding).
fn build_bitstream(message: &[u8], key: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut body = message.to_vec();
    keys::apply_keystream_with_key(&mut body, key);
    let tag = keys::mac_tag_from_key(key, &body);

    let mut framed = Vec::with_capacity(NONCE_BYTES + LEN_BYTES + TAG_BYTES + message.len());
    framed.extend_from_slice(&nonce.to_le_bytes());
    framed.push(message.len() as u8);
    framed.extend_from_slice(&body);
    framed.extend_from_slice(&tag);
    framed
}

/// Seed for the fallback PRNG chooser: keyed so the tail is reproducible
/// for the decoder's replay of decisions (decode only reads framing bits,
/// but keyed fallback keeps the whole path deterministic for testing).
fn fallback_seed(key: &[u8; 32]) -> u64 {
    let d = keys::sha256(&[b"countersteg-fallback", key]);
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

/// Payload capacity estimate (bits) for a score of `len` whole notes.
/// The exact capacity depends on the choices taken; treat this as a
/// lower-bound hint (see `embed`, which verifies the real figure).
pub fn available_bits(nonce: u64, len: usize) -> usize {
    let comp = engine::compose(nonce, len);
    engine::capacity_bits(&comp.decisions)
}

/// Embed a message into a fresh composition. Starts at `min_len` whole-note
/// positions and extends the score until the actual (path-dependent)
/// capacity fits the framing — capacity grows roughly linearly with length.
///
/// `nonce` must be unique per (passphrase, message): it keys the keystream
/// and travels in the framing. Random per message is the safe default.
///
/// Returns the composition (persist it with `write_smf_named(.., None)` —
/// embedded files carry no identifying metadata) and the length that fit.
/// Fails with precise capacity after 128 extensions.
pub fn embed(
    message: &[u8],
    passphrase: &str,
    nonce: u64,
    min_len: usize,
) -> Result<(Composition, usize), StegoError> {
    if message.len() > 255 {
        return Err(StegoError::Decode("message exceeds 255 bytes".into()));
    }
    let needed = framing_bits(message.len());
    // Derive once: stretching is ~100k SHA-256 rounds and the loop below
    // may try many score lengths.
    let key = keys::derive_key(passphrase, nonce);
    let fb = fallback_seed(&key);
    let mut last_capacity = 0usize;
    // Success requires the framing to end exactly on a decision boundary:
    // every framing bit steered, no straddle (a decision whose n bits could
    // not all fit in the remaining stream). 128 extensions (~1000 notes)
    // covers the 255-byte message cap with the 25-byte v2 framing overhead
    // on the current engine's capacity curve (~3 bits per whole note).
    for ext in 0..128 {
        let len = min_len + ext * 8;
        let stream = build_bitstream(message, &key, nonce);
        let mut chooser = PayloadChooser::new(BitReader::new(&stream), fb);
        let comp = compose_with(len, &mut chooser);
        last_capacity = decisions_of(&comp.cf, &comp.cp)
            .map(|ds| engine::capacity_bits(&ds))
            .unwrap_or(0);
        // Success requires the framing to end exactly on a decision
        // boundary: every framing bit steered, no straddle (a decision
        // whose n bits could not all fit in the remaining stream).
        if !chooser.straddled && chooser.consumed_bits() >= needed {
            return Ok((comp, len));
        }
    }
    Err(StegoError::CapacityExceeded {
        needed_bits: needed,
        capacity_bits: last_capacity,
    })
}

/// Extract a message from a composition's notes (decoder side).
/// The nonce is parsed from the framing; only the passphrase is needed.
pub fn extract(cf: &[Note], cp: &[Note], passphrase: &str) -> Result<Vec<u8>, StegoError> {
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

    if bytes.len() < NONCE_BYTES + LEN_BYTES + TAG_BYTES {
        return Err(StegoError::Decode("bitstream too short".into()));
    }
    let nonce = u64::from_le_bytes(bytes[..NONCE_BYTES].try_into().unwrap());
    let claimed = bytes[NONCE_BYTES] as usize;
    if NONCE_BYTES + LEN_BYTES + claimed + TAG_BYTES > bytes.len() {
        return Err(StegoError::WrongKey);
    }
    let key = keys::derive_key(passphrase, nonce);
    let body_start = NONCE_BYTES + LEN_BYTES;
    let mut body = bytes[body_start..body_start + claimed].to_vec();
    let tag: [u8; TAG_BYTES] = bytes[body_start + claimed..body_start + claimed + TAG_BYTES]
        .try_into()
        .unwrap();
    if keys::mac_tag_from_key(&key, &body) != tag {
        return Err(StegoError::WrongKey);
    }
    keys::apply_keystream_with_key(&mut body, &key);
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
        let out = extract(&comp.cf, &comp.cp, "pw").unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn roundtrip_various() {
        for nonce in [1u64, 7, 123] {
            let msg = b"attack at dawn";
            let (comp, _len) = embed(msg, "s3cret", nonce, 16).unwrap();
            let out = extract(&comp.cf, &comp.cp, "s3cret").unwrap();
            assert_eq!(out, msg, "nonce {nonce}");
        }
    }

    #[test]
    fn roundtrip_max_message() {
        // 255 bytes is the cap; it must fit within the 64-extension budget.
        let msg = vec![b'x'; 255];
        let (comp, len) = embed(&msg, "pw", 1, 8).unwrap();
        assert!(len > 8, "extension should have happened");
        let out = extract(&comp.cf, &comp.cp, "pw").unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn wrong_key_fails() {
        let (comp, _) = embed(b"secret", "right", 9, 16).unwrap();
        let res = extract(&comp.cf, &comp.cp, "wrong");
        assert!(matches!(res, Err(StegoError::WrongKey) | Err(StegoError::Decode(_))));
    }

    #[test]
    fn max_message_fits() {
        // The 255-byte cap must fit within the extension budget even with
        // the 25-byte v2 framing overhead (~2240 bits).
        let big = vec![b'x'; 255];
        let (comp, len) = embed(&big, "pw", 1, 8).unwrap();
        assert!(len > 8, "extension should have happened");
        assert_eq!(extract(&comp.cf, &comp.cp, "pw").unwrap(), big);
    }

    #[test]
    fn straddle_extends_until_boundary() {
        // Embed must not return a score whose decision straddles the end of
        // the framing (the v1 corruption bug): every success ends exactly on
        // a decision boundary, so decode must always succeed for any nonce
        // and minimum length that embed accepts.
        for nonce in 0..20u64 {
            let msg = b"boundary probe";
            let (comp, _len) = embed(msg, "pw", nonce, 16).unwrap();
            assert_eq!(
                extract(&comp.cf, &comp.cp, "pw").unwrap(),
                msg,
                "nonce {nonce}"
            );
        }
    }

    #[test]
    fn tail_has_no_candidate_zero_signature() {
        // M4 regression: after the framing is consumed, the fallback PRNG
        // chooser drives the tail. A long score with a 1-byte message must
        // therefore take some non-zero choices late in the path.
        let (comp, len) = embed(b"\xAA", "pw", 3, 64).unwrap();
        assert!(len >= 64);
        let ds = decisions_of(&comp.cf, &comp.cp).unwrap();
        let tail = &ds[ds.len() - 32..];
        assert!(
            tail.iter().any(|d| d.choice > 0),
            "fallback tail picked candidate 0 at every decision (padding signature)"
        );
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
    fn embedded_file_carries_no_identifying_metadata() {
        // M6 regression: embedded files must be indistinguishable from plain
        // MIDI — no track name, no countersteg-identifying byte strings.
        let (comp, _) = embed(b"metadata probe", "pw", 11, 16).unwrap();
        let bytes = engine::write_smf_named(&comp, None);
        let data = engine::read_smf(&bytes).unwrap();
        assert!(data.track_name.is_none(), "embedded file must not carry a track name");
        for marker in [b"countersteg".as_slice(), b"Countersteg", b"seed:", b"nonce"] {
            let found = bytes
                .windows(marker.len())
                .any(|w| w.eq_ignore_ascii_case(marker));
            assert!(!found, "embedded file contains identifying marker {marker:?}");
        }
    }

    #[test]
    fn channel_choices_match_payload_bits() {
        // Encoder invariant: at payload (framing) decisions the choice is
        // the steered bits, so choice < 2^n. Tail decisions are driven by
        // the fallback PRNG and may take any index < arity.
        let msg = b"\xAA";
        let (comp, _) = embed(msg, "pw", 3, 16).unwrap();
        let needed = framing_bits(msg.len());
        let ds = decisions_of(&comp.cf, &comp.cp).unwrap();
        let mut seen = 0usize;
        for d in &ds {
            let n = d.bits();
            if n == 0 {
                continue;
            }
            if seen < needed {
                assert!(d.choice < (1 << n), "payload choice fits n bits");
            }
            seen += n as usize;
        }
        assert!(seen >= needed);
    }
}
