//! stego: selection-channel steganography over the composition engine.
//!
//! The payload does not modify the music after the fact — it *steers* the
//! generator. The framed payload (ciphertext + MAC + framing) is one
//! big-endian integer; at every decision point with `arity >= 1` candidates
//! the chooser pops one mixed-radix digit `s = x mod arity` and takes
//! candidate `s`. The result is genuine first-species counterpoint that
//! happens to encode a ciphertext.
//!
//! Why mixed radix (M7): the v2 design sliced the payload into
//! `n = floor(log2(arity))`-bit chunks, so steered decisions only ever took
//! `2^n` of the `arity` candidates — a biased sub-distribution a warden
//! modeling the engine could detect (MITIGATIONS.md M7). Mixed-radix digits
//! of the pseudorandom (encrypted + MACed) payload integer are uniform over
//! the full arity at every steered decision, head and tail alike, matching
//! the natural generator's distribution (M4). See the `ac` module for the
//! coder and why a binary arithmetic coder was rejected.
//!
//! Payload layout: 0x01 sentinel (nonzero top byte for stable byte
//! serialization) || key-derived IV(16B) || framed body || 0x01 trailer
//! (nonzero bottom byte, same reason). In full:
//! `[0x01][IV 16B][nonce le64][u8 plaintext length][keystream-XOR ciphertext][16-byte MAC tag][0x01]`
//! (messages are capped at 255 bytes — channel capacity is precious).
//!
//! The key-derived IV authenticates the framing boundary before the claimed
//! length is trusted: a wrong key fails here, not on a length check.
//!
//! Species dispatch: `embed` steers first-species whole-note counterpoint
//! (v0.2 behavior, unchanged). `embed_species(.., Species::Second)` steers
//! second-species half-note counterpoint instead — two selection-channel
//! decisions per position, roughly 1.5x the capacity at the same bar count.
//! Extraction auto-detects the species from voice geometry
//! (`cp.len() == cf.len()` vs `2 * cf.len()`), so no species argument is
//! ever needed on the decoder side. Species 1 is permanent: no deprecation,
//! no default swap; species 2 is strictly opt-in per embed.
//!
//! Framing versions: species-1 embeds keep the v0.2 layout
//! (`[0x01][IV][nonce][len][body][MAC][0x01]`) so every v0.2 cover stays
//! readable. Species-2 embeds use the v0.3 layout
//! `[0x03][IV][nonce][species u8][len][body][MAC][0x03]` with a
//! version-separated IV domain — a v0.3 frame can never pass the v0.2
//! boundary check under the same key, and the declared species is
//! cross-checked against the cover's voice geometry before the MAC. The M9
//! ECC region (`[0x02][region x3]`) remains v0.2 species-1 format.
//!
//! M9 error correction (active-warden case): `embed_with_ecc` wraps the
//! region as `[0x02][region x3]` — extraction majority-votes the three
//! copies, so any single-byte corruption of the payload integer is
//! corrected before the MAC is checked. The 0x02 marker is detected on
//! decode, so ECC and non-ECC files interoperate transparently.
//!
//! M10 multi-file consensus: `embed_split` shards a message across several
//! compositions (each shard's payload is `[index][total][len][chunk]`), so
//! no single file carries the whole plaintext; `extract_join` reassembles
//! them, requiring every shard exactly once.
//!
//! Once the payload integer is exhausted, its remaining most-significant
//! mixed-radix digits are 0 and late decisions take candidate 0 — at most a
//! byte's worth of decisions at the very end of the score, far inside the
//! noise floor the M8 self-steganalysis test measures.
//!
//! The nonce is not secret and not metadata: it travels inside the framing
//! and keys the pre-cipher, so reusing a passphrase across messages never
//! reuses a keystream (MITIGATIONS.md M1). Nothing about the file identifies
//! it as countersteg output — the seed the *Compose* path publishes is a
//! public demo convenience and never appears in embedded files.
//!
//! The pre-cipher (keys crate, v2 schedule) runs before channel encoding, so
//! the payload integer is computationally indistinguishable from random.
//!
//! Integrity chain on extract (order matters — each check gates the next):
//!
//! 1. `parse_region` checks both 0x01 markers and that
//!    `MIN_REGION + claimed <= bytes.len()`, so every later slice is
//!    in-bounds; failure is indistinguishable from a wrong key.
//! 2. The key-derived IV check authenticates the framing boundary with the
//!    full 128-bit security of SHA-256 before `claimed` is used as a
//!    length — a wrong key, tampered region, or non-countersteg file is
//!    rejected here, never on an out-of-bounds slice.
//! 3. The 16-byte MAC (Encrypt-then-MAC over the ciphertext body) catches
//!    any remaining tampering of nonce/len/body with ~2^-128 false-accept.
//!    The nonce and len fields are protected transitively: the nonce feeds
//!    key derivation, so flipping it changes the key and fails check 2;
//!    flipping `len` moves the body/tag window and fails the MAC.
//!
//! M9 note: ECC majority-vote runs *before* all of this, so single-byte
//! corruption is repaired while multi-byte corruption still fails closed
//! at the MAC rather than decoding garbage.

use engine::species::second::{compose_with2, decisions_of2, Composition2};
use engine::{compose_with, decisions_of, Chooser, Composition, Decision, Note};

mod ac;
mod bits;
pub use bits::{BitReader, BitWriter};

use ac::BigUint;

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

/// M7 chooser: steers generation by popping one mixed-radix digit per
/// decision from the framed payload integer. Digits of the encrypted + MACed
/// payload are uniform over the full arity, so steered decisions carry no
/// `2^n`-of-arity bias (the v2 chunk chooser's signature, MITIGATIONS.md
/// M7). When the integer is exhausted the digits are 0 — see module docs.
struct AcChooser {
    dec: ac::RadixDecoder,
}

impl Chooser for AcChooser {
    fn choose(&mut self, arity: u32) -> u32 {
        self.dec.decode(arity)
    }
}

/// Payload layout: 0x01 sentinel (nonzero top byte for stable byte
/// serialization) || key-derived IV(16B) || framed body || 0x01 trailer.
/// Both markers are 0x01 so re-serialization of the recovered integer
/// never strips a zero byte at either end.
pub const SENTINEL: u8 = 0x01;
pub const IV_BYTES: usize = 16;
pub const NONCE_BYTES: usize = 8;
pub const LEN_BYTES: usize = 1;
pub const TAG_BYTES: usize = 16;
pub const TRAILER: u8 = 0x01;
/// v0.3 framing: sentinel/trailer for frames that carry a species byte.
pub const SENTINEL_V3: u8 = 0x03;
pub const TRAILER_V3: u8 = 0x03;
/// v0.3 frames insert a species byte between the nonce and the length.
pub const SPECIES_BYTES: usize = 1;
/// sentinel + IV: everything before the nonce.
pub const HEADER_BYTES: usize = 1 + IV_BYTES;
/// smallest possible region: header + nonce + len + tag + trailer.
pub const MIN_REGION: usize = HEADER_BYTES + NONCE_BYTES + LEN_BYTES + TAG_BYTES + 1;
/// smallest possible v0.3 region: the v0.2 minimum plus the species byte.
pub const V3_MIN_REGION: usize = MIN_REGION + SPECIES_BYTES;

/// Counterpoint species: the rule set the CP voice follows. `First` is the
/// v0.2 behavior (whole-note counterpoint, v0.2 framing). `Second` steers
/// the two half notes per position and (see `embed_species`) uses the v0.3
/// framing. Extraction never takes a species argument: the voice geometry
/// (`cp.len()` vs `cf.len()`) disambiguates, and the v0.3 framing carries a
/// species byte cross-checked against that geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Species {
    First,
    Second,
}

/// The steered composition returned by `embed_species`. Callers persist it
/// with `write_smf_named` / `write_smf2_named` (no identifying metadata).
#[derive(Debug)]
pub enum Embedded {
    First(Composition),
    Second(Composition2),
}

/// Species implied by voice geometry: `cp.len() == cf.len()` -> first,
/// `cp.len() == 2 * cf.len()` -> second. Any other ratio is not a
/// countersteg cover (or is corrupt).
fn detect_species(cf: &[Note], cp: &[Note]) -> Option<Species> {
    if cp.len() == cf.len() {
        Some(Species::First)
    } else if cp.len() == 2 * cf.len() {
        Some(Species::Second)
    } else {
        None
    }
}

/// Replay decisions under the species the voice geometry implies.
fn decisions_for(cf: &[Note], cp: &[Note]) -> Result<Vec<Decision>, String> {
    match detect_species(cf, cp) {
        Some(Species::First) => decisions_of(cf, cp),
        Some(Species::Second) => decisions_of2(cf, cp),
        None => Err(format!(
            "cp/cf length ratio {}:{} is not a known species",
            cp.len(),
            cf.len()
        )),
    }
}

/// Replay the decisions of a cover, auto-detecting the species from voice
/// geometry. Public for stats/introspection tools; `extract` uses the same
/// path.
pub fn replay_decisions(cf: &[Note], cp: &[Note]) -> Result<Vec<Decision>, String> {
    decisions_for(cf, cp)
}

/// M9: marks a triplicated region `[0x02][region x3]`; decode majority-votes.
pub const EC_SENTINEL: u8 = 0x02;
/// ECC triples the region, so the message cap shrinks to keep the embed
/// extension budget (128 x 8 notes) sufficient.
pub const EC_MAX_MESSAGE: usize = 64;

/// Region size in bits for a message of `msg_len` bytes.
pub fn framing_bits(msg_len: usize) -> usize {
    (HEADER_BYTES + NONCE_BYTES + LEN_BYTES + TAG_BYTES + msg_len + 1) * 8
}

/// v0.3 region size in bits: the v0.2 layout plus the species byte.
pub fn framing_bits_v3(msg_len: usize) -> usize {
    (HEADER_BYTES + NONCE_BYTES + SPECIES_BYTES + LEN_BYTES + TAG_BYTES + msg_len + 1) * 8
}

fn species_byte(s: Species) -> u8 {
    match s {
        Species::First => 0x01,
        Species::Second => 0x02,
    }
}

fn species_from_byte(b: u8) -> Result<Species, StegoError> {
    match b {
        0x01 => Ok(Species::First),
        0x02 => Ok(Species::Second),
        _ => Err(StegoError::WrongKey),
    }
}

/// Build the framed payload region:
/// `[0x01][iv 16][nonce le64][len u8][keystream-XOR body][tag 16][0x01]`.
fn build_framed(message: &[u8], key: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut body = message.to_vec();
    keys::apply_keystream_with_key(&mut body, key);
    let tag = keys::mac_tag_from_key(key, &body);
    let iv = keys::sha256(&[b"countersteg-ac-iv", key]);

    let mut framed = Vec::with_capacity(MIN_REGION + message.len());
    framed.push(SENTINEL);
    framed.extend_from_slice(&iv[..IV_BYTES]);
    framed.extend_from_slice(&nonce.to_le_bytes());
    framed.push(message.len() as u8);
    framed.extend_from_slice(&body);
    framed.extend_from_slice(&tag);
    framed.push(TRAILER);
    framed
}

/// v0.3 framed region:
/// `[0x03][iv 16][nonce le64][species u8][len u8][body][tag 16][0x03]`.
/// The species byte makes the framing declare which replay the cover must
/// satisfy; `extract_with_key` cross-checks it against voice geometry. The
/// IV uses a v3-specific domain so a v0.3 frame can never pass the v0.2
/// boundary check under the same key (and vice versa) — no downgrade path.
fn build_framed_v3(message: &[u8], key: &[u8; 32], nonce: u64, species: Species) -> Vec<u8> {
    let mut body = message.to_vec();
    keys::apply_keystream_with_key(&mut body, key);
    let tag = keys::mac_tag_from_key(key, &body);
    let iv = keys::sha256(&[b"countersteg-ac-iv-v3", key]);

    let mut framed = Vec::with_capacity(V3_MIN_REGION + message.len());
    framed.push(SENTINEL_V3);
    framed.extend_from_slice(&iv[..IV_BYTES]);
    framed.extend_from_slice(&nonce.to_le_bytes());
    framed.push(species_byte(species));
    framed.push(message.len() as u8);
    framed.extend_from_slice(&body);
    framed.extend_from_slice(&tag);
    framed.push(TRAILER_V3);
    framed
}

/// M9: `[0x02][region x3]` — three copies of the framed region. Decoding
/// majority-votes byte-wise, correcting any single copy's corruption.
fn build_framed_ec(message: &[u8], key: &[u8; 32], nonce: u64) -> Vec<u8> {
    let region = build_framed(message, key, nonce);
    let mut out = Vec::with_capacity(1 + 3 * region.len());
    out.push(EC_SENTINEL);
    for _ in 0..3 {
        out.extend_from_slice(&region);
    }
    out
}

/// M9: strip the triplication marker if present. With three copies a
/// majority always exists (pigeonhole): if copy A disagrees with both
/// others, copies B and C must agree with each other.
fn unwrap_ec(bytes: &[u8]) -> Result<Vec<u8>, StegoError> {
    if bytes.first() != Some(&EC_SENTINEL) {
        return Ok(bytes.to_vec());
    }
    let rest = &bytes[1..];
    if rest.is_empty() || rest.len() % 3 != 0 {
        return Err(StegoError::Decode("corrupt triplicated region".into()));
    }
    let n = rest.len() / 3;
    let (a, b, c) = (&rest[..n], &rest[n..2 * n], &rest[2 * n..]);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(if a[i] == b[i] || a[i] == c[i] { a[i] } else { b[i] });
    }
    Ok(out)
}

/// Capacity of a decision path in bits: `floor(sum(log2(arity)))` over the
/// path's arities. The mixed-radix channel carries `log2(product)` bits, so
/// this is the honest capacity measure (v2's `sum(floor(log2))` per-decision
/// chunking understated it and forced the bias M7 removes).
fn path_bits(decisions: &[Decision]) -> usize {
    let sum: f64 = decisions.iter().map(|d| (d.arity.max(1) as f64).log2()).sum();
    sum.floor() as usize
}

/// Replay the decisions and rebuild the payload integer, then serialize it
/// (minimal big-endian; the sentinel/trailer bytes keep both ends stable).
fn rebuild(decisions: &[Decision]) -> Vec<u8> {
    let mut enc = ac::RadixEncoder::new();
    for d in decisions.iter().rev() {
        enc.encode(d.choice, d.arity);
    }
    enc.finish().to_be_bytes()
}

/// Framing version, read off the sentinel/trailer pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    V2,
    V3,
}

/// Parsed region header: everything `extract_with_key` needs after the
/// layout check, before the MAC.
struct Region {
    framing: Framing,
    nonce: u64,
    claimed: usize,
    species: Species,
    body_start: usize,
}

/// Parse the region header out of a rebuilt payload and return the framing
/// version, nonce, claimed length, declared species, and body offset.
/// Marker, layout, and bounds failures are indistinguishable from a wrong
/// key.
fn parse_region(bytes: &[u8]) -> Result<Region, StegoError> {
    let framing = match (bytes.first(), bytes.last()) {
        (Some(&SENTINEL), Some(&TRAILER)) => Framing::V2,
        (Some(&SENTINEL_V3), Some(&TRAILER_V3)) => Framing::V3,
        _ => return Err(StegoError::WrongKey),
    };
    let min_region = match framing {
        Framing::V2 => MIN_REGION,
        Framing::V3 => V3_MIN_REGION,
    };
    if bytes.len() < min_region {
        return Err(StegoError::Decode("region too short".into()));
    }
    let nonce = u64::from_le_bytes(
        bytes[HEADER_BYTES..HEADER_BYTES + NONCE_BYTES]
            .try_into()
            .unwrap(),
    );
    let (species, len_pos) = match framing {
        Framing::V2 => (Species::First, HEADER_BYTES + NONCE_BYTES),
        Framing::V3 => {
            let s = species_from_byte(bytes[HEADER_BYTES + NONCE_BYTES])?;
            (s, HEADER_BYTES + NONCE_BYTES + SPECIES_BYTES)
        }
    };
    let claimed = bytes[len_pos] as usize;
    if bytes.len() < min_region + claimed {
        return Err(StegoError::WrongKey);
    }
    Ok(Region {
        framing,
        nonce,
        claimed,
        species,
        body_start: len_pos + LEN_BYTES,
    })
}

/// Payload capacity estimate (bits) for a score of `len` whole notes.
/// The exact capacity depends on the path taken; treat this as a
/// lower-bound hint (see `embed`, which verifies the real figure).
pub fn available_bits(nonce: u64, len: usize) -> usize {
    available_bits_species(nonce, len, Species::First)
}

/// Like `available_bits`, for either species. Second species carries the
/// two CP beats per position as separate decisions, so its channel is
/// roughly 1.5x wider at the same bar count.
pub fn available_bits_species(nonce: u64, len: usize, species: Species) -> usize {
    match species {
        Species::First => path_bits(&engine::compose(nonce, len).decisions),
        Species::Second => path_bits(&engine::species::second::compose2(nonce, len).decisions),
    }
}

/// Extend the score from `min_len` until the steered path covers `needed`
/// bits *and* a full in-process extraction reproduces the message (the
/// self-check is authoritative — capacity arithmetic alone is only a hint).
/// Fails with precise capacity after 128 extensions.
fn embed_loop(
    payload: &BigUint,
    key: &[u8; 32],
    message: &[u8],
    needed: usize,
    min_len: usize,
    species: Species,
) -> Result<(Embedded, usize), StegoError> {
    let mut last_capacity = 0usize;
    for ext in 0..128 {
        let len = min_len + ext * 8;
        let mut chooser = AcChooser {
            dec: ac::RadixDecoder::new(payload.clone()),
        };
        match species {
            Species::First => {
                let comp = compose_with(len, &mut chooser);
                last_capacity = decisions_of(&comp.cf, &comp.cp)
                    .map(|ds| path_bits(&ds))
                    .unwrap_or(0);
                if last_capacity >= needed
                    && matches!(
                        extract_with_key(&comp.cf, &comp.cp, key).as_deref(),
                        Ok(out) if out == message
                    )
                {
                    return Ok((Embedded::First(comp), len));
                }
            }
            Species::Second => {
                let comp = compose_with2(len, &mut chooser);
                last_capacity = decisions_of2(&comp.cf, &comp.cp)
                    .map(|ds| path_bits(&ds))
                    .unwrap_or(0);
                if last_capacity >= needed
                    && matches!(
                        extract_with_key(&comp.cf, &comp.cp, key).as_deref(),
                        Ok(out) if out == message
                    )
                {
                    return Ok((Embedded::Second(comp), len));
                }
            }
        }
    }
    Err(StegoError::CapacityExceeded {
        needed_bits: needed,
        capacity_bits: last_capacity,
    })
}

/// Embed a message into a fresh composition. Starts at `min_len` whole-note
/// positions and extends the score until the path capacity covers the
/// payload region *and* a full in-process extraction reproduces the message
/// (the self-check is authoritative — capacity arithmetic alone is only a
/// hint).
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
    // Derive once: stretching is ~100k SHA-256 rounds and the loop below
    // may try many score lengths.
    let key = keys::derive_key(passphrase, nonce);
    let framed = build_framed(message, &key, nonce);
    let payload = BigUint::from_be_bytes(&framed);
    match embed_loop(&payload, &key, message, framing_bits(message.len()), min_len, Species::First)? {
        (Embedded::First(comp), len) => Ok((comp, len)),
        _ => unreachable!("embed is species-1 only"),
    }
}

/// Second-species embed: like `embed`, but the CP voice carries two half
/// notes per position (see `engine::species::second`), roughly 1.5x the
/// channel capacity at the same bar count. Persist with
/// `write_smf2_named(.., None)`.
pub fn embed_species(
    message: &[u8],
    passphrase: &str,
    nonce: u64,
    min_len: usize,
    species: Species,
) -> Result<(Embedded, usize), StegoError> {
    if message.len() > 255 {
        return Err(StegoError::Decode("message exceeds 255 bytes".into()));
    }
    let key = keys::derive_key(passphrase, nonce);
    // Framing per species: First keeps the v0.2 layout (species-1 covers
    // remain readable by v0.2 decoders); Second uses the v0.3 frame with its
    // declared species byte.
    let (framed, needed) = match species {
        Species::First => (build_framed(message, &key, nonce), framing_bits(message.len())),
        Species::Second => (
            build_framed_v3(message, &key, nonce, species),
            framing_bits_v3(message.len()),
        ),
    };
    let payload = BigUint::from_be_bytes(&framed);
    embed_loop(&payload, &key, message, needed, min_len, species)
}

/// M9: like `embed`, but the region is triplicated so that extraction
/// survives any single-byte corruption of the payload integer (majority
/// vote). Costs 3x capacity; message cap is `EC_MAX_MESSAGE` (64 bytes).
/// ECC regions stay in the v0.2 species-1 format (decision D3).
pub fn embed_with_ecc(
    message: &[u8],
    passphrase: &str,
    nonce: u64,
    min_len: usize,
) -> Result<(Composition, usize), StegoError> {
    if message.len() > EC_MAX_MESSAGE {
        return Err(StegoError::Decode(format!(
            "message exceeds {EC_MAX_MESSAGE} bytes"
        )));
    }
    let key = keys::derive_key(passphrase, nonce);
    let framed = build_framed_ec(message, &key, nonce);
    let payload = BigUint::from_be_bytes(&framed);
    let needed = (1 + 3 * (MIN_REGION + message.len())) * 8;
    match embed_loop(&payload, &key, message, needed, min_len, Species::First)? {
        (Embedded::First(comp), len) => Ok((comp, len)),
        _ => unreachable!("ECC embed is species-1 only"),
    }
}

/// Extract a message from a composition's notes with an already-derived key
/// (decoder side; `extract` derives the key from the parsed nonce first).
pub fn extract_with_key(cf: &[Note], cp: &[Note], key: &[u8; 32]) -> Result<Vec<u8>, StegoError> {
    let decisions = decisions_for(cf, cp).map_err(StegoError::Decode)?;
    let bytes = unwrap_ec(&rebuild(&decisions))?;
    let region = parse_region(&bytes)?;

    // Cross-check: the framing-declared species must agree with the cover's
    // voice geometry (the replay above already pinned it). The MAC would
    // catch a flip downstream too, but a disagreement here is tampering —
    // fail closed, indistinguishable from a wrong key.
    if detect_species(cf, cp) != Some(region.species) {
        return Err(StegoError::WrongKey);
    }

    // The key-derived IV authenticates the framing boundary with the
    // version-specific domain: anything but the exact key fails here before
    // `claimed` is ever used as a length.
    let iv_domain: &[u8] = match region.framing {
        Framing::V2 => b"countersteg-ac-iv",
        Framing::V3 => b"countersteg-ac-iv-v3",
    };
    let iv = keys::sha256(&[iv_domain, key]);
    if bytes[1..HEADER_BYTES] != iv[..IV_BYTES] {
        return Err(StegoError::WrongKey);
    }

    let body_start = region.body_start;
    let mut body = bytes[body_start..body_start + region.claimed].to_vec();
    let tag: [u8; TAG_BYTES] = bytes[body_start + region.claimed..body_start + region.claimed + TAG_BYTES]
        .try_into()
        .unwrap();
    if keys::mac_tag_from_key(key, &body) != tag {
        return Err(StegoError::WrongKey);
    }
    keys::apply_keystream_with_key(&mut body, key);
    Ok(body)
}

/// Extract a message from a composition's notes (decoder side).
/// The nonce is parsed from the framing; only the passphrase is needed.
pub fn extract(cf: &[Note], cp: &[Note], passphrase: &str) -> Result<Vec<u8>, StegoError> {
    let decisions = decisions_for(cf, cp).map_err(StegoError::Decode)?;
    let bytes = unwrap_ec(&rebuild(&decisions))?;
    let region = parse_region(&bytes)?;
    let key = keys::derive_key(passphrase, region.nonce);
    extract_with_key(cf, cp, &key)
}

/// M10: split a message across `count` compositions so no single file
/// carries the whole plaintext. Each shard embeds
/// `[index u8][total u8][len u8][chunk]` through the normal path; shard
/// `i` uses `nonce + i`, so `nonce` must be unique per (passphrase,
/// message) as usual — random per message is the safe default.
///
/// Chunk size is `ceil(len / count)` and must fit the per-file u8 length
/// field (252 bytes): raise `count` for longer messages.
pub fn embed_split(
    message: &[u8],
    passphrase: &str,
    nonce: u64,
    count: usize,
    min_len: usize,
) -> Result<Vec<Composition>, StegoError> {
    if count < 2 || count > 255 {
        return Err(StegoError::Decode("shard count must be 2..=255".into()));
    }
    if message.is_empty() {
        return Err(StegoError::Decode("empty message".into()));
    }
    let chunk = (message.len() + count - 1) / count;
    if chunk > 252 {
        return Err(StegoError::Decode(
            "message too long for shard count; raise count".into(),
        ));
    }
    let mut comps = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * chunk;
        let part = &message[start..(start + chunk).min(message.len())];
        let mut payload = Vec::with_capacity(3 + part.len());
        payload.push(i as u8);
        payload.push(count as u8);
        payload.push(part.len() as u8);
        payload.extend_from_slice(part);
        let (comp, _) = embed(&payload, passphrase, nonce.wrapping_add(i as u64), min_len)?;
        comps.push(comp);
    }
    Ok(comps)
}

/// M10: reassemble a message split by `embed_split`. Every shard must be
/// present exactly once and must declare the same total; any mismatch is
/// a decode error (a withheld or substituted shard is detectable).
pub fn extract_join(parts: &[(Vec<Note>, Vec<Note>)], passphrase: &str) -> Result<Vec<u8>, StegoError> {
    if parts.is_empty() {
        return Err(StegoError::Decode("no shards".into()));
    }
    let mut shards: Vec<(u8, u8, Vec<u8>)> = Vec::with_capacity(parts.len());
    for (cf, cp) in parts {
        let payload = extract(cf, cp, passphrase)?;
        if payload.len() < 3 {
            return Err(StegoError::Decode("shard payload too short".into()));
        }
        let (index, total, slen) = (payload[0], payload[1], payload[2] as usize);
        if payload.len() != 3 + slen {
            return Err(StegoError::Decode("corrupt shard payload".into()));
        }
        shards.push((index, total, payload[3..].to_vec()));
    }
    let total = shards[0].1;
    let mut seen = vec![false; total as usize];
    let mut ordered: Vec<Option<&[u8]>> = vec![None; total as usize];
    for (index, t, chunk) in &shards {
        if *t != total {
            return Err(StegoError::Decode("inconsistent shard totals".into()));
        }
        let slot = ordered.get_mut(*index as usize).ok_or_else(|| {
            StegoError::Decode("shard index out of range".to_string())
        })?;
        if seen[*index as usize] || slot.is_some() {
            return Err(StegoError::Decode("duplicate shard".into()));
        }
        seen[*index as usize] = true;
        *slot = Some(chunk);
    }
    if ordered.iter().any(|s| s.is_none()) {
        return Err(StegoError::Decode("missing shard".into()));
    }
    let mut out = Vec::new();
    for chunk in ordered {
        out.extend_from_slice(chunk.unwrap());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::theory::is_consonant;
    use std::collections::BTreeMap;

    /// Per-arity choice tallies: arity -> count per candidate index.
    fn tally(decisions: &[Decision]) -> BTreeMap<u32, Vec<u32>> {
        let mut t: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for d in decisions {
            let v = t.entry(d.arity).or_insert_with(|| vec![0; d.arity as usize]);
            v[d.choice as usize] += 1;
        }
        t
    }

    /// Total variation distance between two per-arity tally maps.
    fn total_variation(a: &BTreeMap<u32, Vec<u32>>, b: &BTreeMap<u32, Vec<u32>>) -> BTreeMap<u32, f64> {
        let mut tv = BTreeMap::new();
        for arity in a.keys().chain(b.keys()).copied().collect::<std::collections::BTreeSet<_>>() {
            let (ta, tb) = (a.get(&arity), b.get(&arity));
            let na: u32 = ta.map(|v| v.iter().sum()).unwrap_or(0);
            let nb: u32 = tb.map(|v| v.iter().sum()).unwrap_or(0);
            if na == 0 || nb == 0 {
                continue;
            }
            let mut d = 0.0;
            for i in 0..(arity as usize) {
                let pa = ta.map(|v| v[i] as f64 / na as f64).unwrap_or(0.0);
                let pb = tb.map(|v| v[i] as f64 / nb as f64).unwrap_or(0.0);
                d += (pa - pb).abs();
            }
            tv.insert(arity, 0.5 * d);
        }
        tv
    }

    /// End-to-end known-answer vector pinning the exact framed-region bytes
    /// for fixed (passphrase, nonce, message): key schedule -> keystream-XOR
    /// -> MAC -> framing layout. A regression anywhere in that chain changes
    /// these bytes and fails here, where a roundtrip test alone would still
    /// pass (encrypt/decrypt errors cancel). Vectors captured from real runs
    /// of the v2 construction (see crates/keys/tests for primitive-level KATs).
    #[test]
    fn framed_region_known_answers() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let key = keys::derive_key("integrity vector", 0x0102030405060708);
        assert_eq!(
            hex(&build_framed(b"vector", &key, 0x0102030405060708)),
            "01bc51cf581f59c04d3e01c909c506bed6\
             08070605040302010603894c3e7cd6d7\
             00212dd83416ea9317d82c2dac3d4801"
        );
        // Minimal region: empty body is still keystream-XORed + MACed.
        assert_eq!(
            hex(&build_framed(b"", &key, 0)),
            "01bc51cf581f59c04d3e01c909c506bed6\
             000000000000000000\
             a63e590505b2189223962b7db9f705fc01"
        );
        // M9 triplication is exactly [0x02][region x3].
        let ec = build_framed_ec(b"vector", &key, 0x0102030405060708);
        assert_eq!(ec.len(), 1 + 3 * (MIN_REGION + 6));
        assert_eq!(&ec[..1], &[EC_SENTINEL]);
        assert_eq!(&ec[1..1 + 49], &build_framed(b"vector", &key, 0x0102030405060708)[..]);
    }

    /// v0.3 known-answer vectors, same construction as
    /// `framed_region_known_answers`: pins the v3 sentinel, the
    /// version-separated IV domain, the species byte, and the trailer.
    /// Captured from real runs; a regression anywhere in that chain changes
    /// these bytes and fails here.
    #[test]
    fn framed_v3_known_answers() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let key = keys::derive_key("integrity vector", 0x0102030405060708);
        assert_eq!(
            hex(&build_framed_v3(b"vector", &key, 0x0102030405060708, Species::Second)),
            "037b2f517f52709d0184c95fe91daf3171\
             0807060504030201020603\
             894c3e7cd6d700212dd83416ea9317d82c2dac3d4803"
        );
        // Minimal region with the species-1 byte: still v3 framing.
        assert_eq!(
            hex(&build_framed_v3(b"", &key, 0, Species::First)),
            "037b2f517f52709d0184c95fe91daf3171\
             00000000000000000100\
             a63e590505b2189223962b7db9f705fc03"
        );
    }

    #[test]
    fn framed_v3_layout_and_stable_ends() {
        let key = keys::derive_key("pw", 42);
        let framed = build_framed_v3(b"hi", &key, 42, Species::Second);
        assert_eq!(framed[0], SENTINEL_V3);
        assert_eq!(framed[framed.len() - 1], TRAILER_V3);
        assert_eq!(framed.len(), V3_MIN_REGION + 2);
        assert_eq!(framed[HEADER_BYTES + NONCE_BYTES], 0x02); // species byte
        let x = BigUint::from_be_bytes(&framed);
        assert_eq!(x.to_be_bytes(), framed);
    }

    #[test]
    fn v3_rejects_bad_species_byte() {
        let key = keys::derive_key("pw", 9);
        let mut framed = build_framed_v3(b"hi", &key, 9, Species::Second);
        framed[HEADER_BYTES + NONCE_BYTES] = 0x07;
        assert!(matches!(parse_region(&framed), Err(StegoError::WrongKey)));
    }

    #[test]
    fn v2_and_v3_parse_under_their_own_layout() {
        let key = keys::derive_key("pw", 9);
        let v2 = build_framed(b"hi", &key, 9);
        let r2 = parse_region(&v2).unwrap();
        assert_eq!(r2.framing, Framing::V2);
        assert_eq!(r2.species, Species::First);
        // A v3 frame declaring species 1 parses too — the parser accepts
        // any declared species; embed never produces this combination.
        let v3 = build_framed_v3(b"hi", &key, 9, Species::First);
        let r3 = parse_region(&v3).unwrap();
        assert_eq!(r3.framing, Framing::V3);
        assert_eq!(r3.species, Species::First);
    }

    #[test]
    fn v3_species_geometry_crosscheck_rejects_mismatch() {
        // A v3 frame declaring species 2 steered into a species-1 cover must
        // fail closed at the geometry cross-check, not decode garbage.
        let key = keys::derive_key("pw", 5);
        let framed = build_framed_v3(b"hi", &key, 5, Species::Second);
        let payload = BigUint::from_be_bytes(&framed);
        let mut chooser = AcChooser {
            dec: ac::RadixDecoder::new(payload),
        };
        let comp = compose_with(16, &mut chooser);
        let res = extract_with_key(&comp.cf, &comp.cp, &key);
        assert!(matches!(res, Err(StegoError::WrongKey)));
    }

    #[test]
    fn species2_embed_uses_v3_framing() {
        let msg = b"framing probe";
        let (comp, _) = embed_species(msg, "pw", 7, 16, Species::Second).unwrap();
        let (cf, cp) = match &comp {
            Embedded::Second(c) => (&c.cf, &c.cp),
            Embedded::First(_) => panic!("expected second species"),
        };
        let ds = decisions_for(cf, cp).unwrap();
        let bytes = unwrap_ec(&rebuild(&ds)).unwrap();
        let region = parse_region(&bytes).unwrap();
        assert_eq!(region.framing, Framing::V3);
        assert_eq!(region.species, Species::Second);
        assert_eq!(extract(cf, cp, "pw").unwrap(), msg);
    }

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
    fn roundtrip_species2() {
        // Auto-detection proof: extract() takes no species argument; the
        // voice geometry (cp.len() == 2 * cf.len()) drives the replay.
        let msg = b"second species payload";
        let (comp, len) = embed_species(msg, "pw", 42, 16, Species::Second).unwrap();
        let (cf, cp) = match &comp {
            Embedded::First(_) => panic!("expected a second-species composition"),
            Embedded::Second(c) => (c.cf.clone(), c.cp.clone()),
        };
        assert_eq!(cp.len(), 2 * cf.len());
        assert_eq!(extract(&cf, &cp, "pw").unwrap(), msg);
        assert_eq!(extract_with_key(&cf, &cp, &keys::derive_key("pw", 42)).unwrap(), msg);
        let _ = len;
    }

    #[test]
    fn species2_capacity_exceeds_species1() {
        // Same bar count, both species: the half-note grid is strictly wider.
        for nonce in 0..8u64 {
            for len in [8usize, 16, 32] {
                let s1 = available_bits_species(nonce, len, Species::First);
                let s2 = available_bits_species(nonce, len, Species::Second);
                assert!(s2 > s1, "nonce {nonce} len {len}: species2 {s2} <= species1 {s1}");
            }
        }
    }

    #[test]
    fn replay_rejects_unknown_geometry() {
        // cp lengths that match neither species are a decode error, not a
        // panic or a mis-dispatch.
        let cf: Vec<Note> = engine::compose(1, 8).cf;
        let short_cp: Vec<Note> = engine::compose(1, 8).cp[..7].to_vec();
        let res = extract(&cf, &short_cp, "pw");
        assert!(matches!(res, Err(StegoError::Decode(_))));
    }

    #[test]
    fn roundtrip_max_message() {
        // 255 bytes is the cap; it must fit within the extension budget.
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
        // the 43-byte region overhead (~2384 bits).
        let big = vec![b'x'; 255];
        let (comp, len) = embed(&big, "pw", 1, 8).unwrap();
        assert!(len > 8, "extension should have happened");
        assert_eq!(extract(&comp.cf, &comp.cp, "pw").unwrap(), big);
    }

    #[test]
    fn extension_finds_fitting_length() {
        // Every accepted (nonce, min_len) must roundtrip: the embed
        // self-check replays the full extraction before returning.
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

    /// M8: the warden's own test. Embed across 24 fixed seeds and compare
    /// the per-arity choice distribution against the natural `compose`
    /// baseline. Total variation must stay under 0.15 for every arity —
    /// the same threshold a warden would use to separate the two.
    #[test]
    fn self_steganalysis_distribution_matches_natural() {
        let msg = b"distribution probe";
        let len = 64;
        let mut embedded: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut natural: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for seed in 0..24u64 {
            let (comp, _) = embed(msg, "pw", 1_000 + seed, len).unwrap();
            let ds = decisions_of(&comp.cf, &comp.cp).unwrap();
            for (arity, counts) in tally(&ds) {
                let v = embedded.entry(arity).or_insert_with(|| vec![0; arity as usize]);
                for (i, c) in counts.iter().enumerate() {
                    v[i] += c;
                }
            }
            let nat = engine::compose(seed, len);
            for (arity, counts) in tally(&nat.decisions) {
                let v = natural.entry(arity).or_insert_with(|| vec![0; arity as usize]);
                for (i, c) in counts.iter().enumerate() {
                    v[i] += c;
                }
            }
        }
        let tv = total_variation(&embedded, &natural);
        assert!(!tv.is_empty(), "no overlapping arity buckets");
        for (arity, d) in tv {
            assert!(d < 0.15, "arity {arity}: total variation {d:.3} vs natural");
        }
    }

    /// M7: steered decisions must use the FULL candidate range at every
    /// arity, not just `2^n` of it (the v2 chunk-chooser bias).
    #[test]
    fn payload_choices_use_full_arity() {
        // Aggregate across 12 nonces: uniform digits must collectively hit
        // every candidate at every arity (a single short path may miss one).
        let mut agg: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for nonce in 0..12u64 {
            let (comp, _) = embed(b"\xAA", "pw", nonce, 32).unwrap();
            let ds = decisions_of(&comp.cf, &comp.cp).unwrap();
            for (arity, counts) in tally(&ds) {
                let v = agg.entry(arity).or_insert_with(|| vec![0; arity as usize]);
                for (i, c) in counts.iter().enumerate() {
                    v[i] += c;
                }
            }
        }
        for (arity, counts) in agg {
            for (i, &c) in counts.iter().enumerate() {
                assert!(c > 0, "arity {arity}: candidate {i} never taken");
            }
        }
    }

    /// The framing boundary is authenticated by the key-derived IV before
    /// the claimed length is trusted: flipping a note must not decode.
    #[test]
    fn tampered_score_fails() {
        let (mut comp, _) = embed(b"integrity probe", "pw", 77, 16).unwrap();
        let i = comp.cf.len() / 2;
        comp.cp[i] = comp.cf[i]; // break the counterpoint relationship
        let res = extract(&comp.cf, &comp.cp, "pw");
        assert!(matches!(res, Err(StegoError::WrongKey) | Err(StegoError::Decode(_))));
    }

    #[test]
    fn framed_region_has_stable_end_bytes() {
        // Sentinel and trailer survive the integer round trip.
        let key = keys::derive_key("pw", 42);
        let framed = build_framed(b"hi", &key, 42);
        assert_eq!(framed[0], SENTINEL);
        assert_eq!(framed[framed.len() - 1], TRAILER);
        let x = BigUint::from_be_bytes(&framed);
        assert_eq!(x.to_be_bytes(), framed);
    }

    #[test]
    fn roundtrip_with_ecc() {
        for nonce in [1u64, 7] {
            let msg = b"correct the active warden";
            let (comp, _len) = embed_with_ecc(msg, "pw", nonce, 16).unwrap();
            assert_eq!(extract(&comp.cf, &comp.cp, "pw").unwrap(), msg, "nonce {nonce}");
        }
    }

    #[test]
    fn ecc_roundtrip_max_message() {
        let msg = vec![b'x'; EC_MAX_MESSAGE];
        let (comp, _len) = embed_with_ecc(&msg, "pw", 3, 8).unwrap();
        assert_eq!(extract(&comp.cf, &comp.cp, "pw").unwrap(), msg);
    }

    #[test]
    fn ecc_majority_recovers_single_copy_corruption() {
        let key = keys::derive_key("pw", 9);
        let region = build_framed(b"hi", &key, 9);
        let mut tri = build_framed_ec(b"hi", &key, 9);
        assert_eq!(tri[0], EC_SENTINEL);
        let n = region.len();
        // Corrupt one byte in each copy at different positions.
        tri[1 + 2] ^= 0xFF;
        tri[1 + n + 5] ^= 0xFF;
        tri[1 + 2 * n + 0] ^= 0xFF;
        assert_eq!(unwrap_ec(&tri).unwrap(), region);
    }

    #[test]
    fn ecc_rejects_bad_layout() {
        assert!(unwrap_ec(&[EC_SENTINEL]).is_err());
        assert!(unwrap_ec(&[EC_SENTINEL, 1, 2]).is_err());
        // Non-ECC payloads pass through untouched.
        assert_eq!(unwrap_ec(&[0x01, 0x02]).unwrap(), vec![0x01, 0x02]);
    }

    #[test]
    fn ecc_oversize_message_rejected() {
        let big = vec![b'x'; EC_MAX_MESSAGE + 1];
        let res = embed_with_ecc(&big, "pw", 1, 16);
        assert!(matches!(res, Err(StegoError::Decode(_))));
    }

    #[test]
    fn split_join_roundtrip() {
        // 600 bytes exceeds the single-file cap; three shards carry it.
        let msg: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
        let comps = embed_split(&msg, "pw", 555, 3, 8).unwrap();
        assert_eq!(comps.len(), 3);
        let parts: Vec<_> = comps.iter().map(|c| (c.cf.clone(), c.cp.clone())).collect();
        assert_eq!(extract_join(&parts, "pw").unwrap(), msg);
    }

    #[test]
    fn split_join_rejects_missing_shard() {
        let msg: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let comps = embed_split(&msg, "pw", 556, 3, 8).unwrap();
        let parts: Vec<_> = comps.iter().take(2).map(|c| (c.cf.clone(), c.cp.clone())).collect();
        let res = extract_join(&parts, "pw");
        assert!(matches!(res, Err(StegoError::Decode(_))));
    }

    #[test]
    fn split_join_rejects_mixed_sets() {
        let a = embed_split(b"aaaa", "pw", 557, 2, 8).unwrap();
        let b = embed_split(b"bbbb", "pw", 900, 3, 8).unwrap();
        let mut parts: Vec<_> = a.iter().map(|c| (c.cf.clone(), c.cp.clone())).collect();
        parts.push((b[0].cf.clone(), b[0].cp.clone()));
        let res = extract_join(&parts, "pw");
        assert!(matches!(res, Err(StegoError::Decode(_))));
    }

    #[test]
    fn split_rejects_too_few_shards_for_length() {
        // 600 bytes / 2 shards = 300-byte chunks > 252-byte u8 field.
        let msg = vec![b'x'; 600];
        let res = embed_split(&msg, "pw", 558, 2, 8);
        assert!(matches!(res, Err(StegoError::Decode(_))));
    }
}