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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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
/// sentinel + IV: everything before the nonce.
pub const HEADER_BYTES: usize = 1 + IV_BYTES;
/// smallest possible region: header + nonce + len + tag + trailer.
pub const MIN_REGION: usize = HEADER_BYTES + NONCE_BYTES + LEN_BYTES + TAG_BYTES + 1;

/// M9: marks a triplicated region `[0x02][region x3]`; decode majority-votes.
pub const EC_SENTINEL: u8 = 0x02;
/// ECC triples the region, so the message cap shrinks to keep the embed
/// extension budget (128 x 8 notes) sufficient.
pub const EC_MAX_MESSAGE: usize = 64;

/// Region size in bits for a message of `msg_len` bytes.
pub fn framing_bits(msg_len: usize) -> usize {
    (HEADER_BYTES + NONCE_BYTES + LEN_BYTES + TAG_BYTES + msg_len + 1) * 8
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

/// Parse `[sentinel][IV][nonce][len]` out of a rebuilt region and return
/// `(nonce, claimed_len)`. Marker and bounds failures are indistinguishable
/// from a wrong key.
fn parse_region(bytes: &[u8]) -> Result<(u64, usize), StegoError> {
    if bytes.first() != Some(&SENTINEL) || bytes.last() != Some(&TRAILER) {
        return Err(StegoError::WrongKey);
    }
    if bytes.len() < MIN_REGION {
        return Err(StegoError::Decode("region too short".into()));
    }
    let nonce = u64::from_le_bytes(
        bytes[HEADER_BYTES..HEADER_BYTES + NONCE_BYTES]
            .try_into()
            .unwrap(),
    );
    let claimed = bytes[HEADER_BYTES + NONCE_BYTES] as usize;
    if bytes.len() < MIN_REGION + claimed {
        return Err(StegoError::WrongKey);
    }
    Ok((nonce, claimed))
}

/// Payload capacity estimate (bits) for a score of `len` whole notes.
/// The exact capacity depends on the path taken; treat this as a
/// lower-bound hint (see `embed`, which verifies the real figure).
pub fn available_bits(nonce: u64, len: usize) -> usize {
    let comp = engine::compose(nonce, len);
    path_bits(&comp.decisions)
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
    embed_inner(message, passphrase, nonce, min_len, false)
}

/// M9: like `embed`, but the region is triplicated so that extraction
/// survives any single-byte corruption of the payload integer (majority
/// vote). Costs 3x capacity; message cap is `EC_MAX_MESSAGE` (64 bytes).
pub fn embed_with_ecc(
    message: &[u8],
    passphrase: &str,
    nonce: u64,
    min_len: usize,
) -> Result<(Composition, usize), StegoError> {
    embed_inner(message, passphrase, nonce, min_len, true)
}

fn embed_inner(
    message: &[u8],
    passphrase: &str,
    nonce: u64,
    min_len: usize,
    ecc: bool,
) -> Result<(Composition, usize), StegoError> {
    let max_msg = if ecc { EC_MAX_MESSAGE } else { 255 };
    if message.len() > max_msg {
        return Err(StegoError::Decode(format!(
            "message exceeds {max_msg} bytes"
        )));
    }
    let needed = if ecc {
        (1 + 3 * (MIN_REGION + message.len())) * 8
    } else {
        framing_bits(message.len())
    };
    // Derive once: stretching is ~100k SHA-256 rounds and the loop below
    // may try many score lengths.
    let key = keys::derive_key(passphrase, nonce);
    let framed = if ecc {
        build_framed_ec(message, &key, nonce)
    } else {
        build_framed(message, &key, nonce)
    };
    let payload = BigUint::from_be_bytes(&framed);
    let mut last_capacity = 0usize;
    for ext in 0..128 {
        let len = min_len + ext * 8;
        let mut chooser = AcChooser {
            dec: ac::RadixDecoder::new(payload.clone()),
        };
        let comp = compose_with(len, &mut chooser);
        last_capacity = decisions_of(&comp.cf, &comp.cp)
            .map(|ds| path_bits(&ds))
            .unwrap_or(0);
        if last_capacity >= needed
            && matches!(
                extract_with_key(&comp.cf, &comp.cp, &key).as_deref(),
                Ok(out) if out == message
            )
        {
            return Ok((comp, len));
        }
    }
    Err(StegoError::CapacityExceeded {
        needed_bits: needed,
        capacity_bits: last_capacity,
    })
}

/// Extract a message from a composition's notes with an already-derived key
/// (decoder side; `extract` derives the key from the parsed nonce first).
pub fn extract_with_key(cf: &[Note], cp: &[Note], key: &[u8; 32]) -> Result<Vec<u8>, StegoError> {
    let decisions = decisions_of(cf, cp).map_err(StegoError::Decode)?;
    let bytes = unwrap_ec(&rebuild(&decisions))?;
    let (_nonce, claimed) = parse_region(&bytes)?;

    // The key-derived IV authenticates the framing boundary: anything but
    // the exact key fails here before `claimed` is ever used as a length.
    let iv = keys::sha256(&[b"countersteg-ac-iv", key]);
    if bytes[1..HEADER_BYTES] != iv[..IV_BYTES] {
        return Err(StegoError::WrongKey);
    }

    let body_start = HEADER_BYTES + NONCE_BYTES + LEN_BYTES;
    let mut body = bytes[body_start..body_start + claimed].to_vec();
    let tag: [u8; TAG_BYTES] = bytes[body_start + claimed..body_start + claimed + TAG_BYTES]
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
    let decisions = decisions_of(cf, cp).map_err(StegoError::Decode)?;
    let bytes = unwrap_ec(&rebuild(&decisions))?;
    let (nonce, _claimed) = parse_region(&bytes)?;
    let key = keys::derive_key(passphrase, nonce);
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
        let (comp, _) = embed_inner(&payload, passphrase, nonce.wrapping_add(i as u64), min_len, false)?;
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

    #[test]
    fn roundtrip_short_message() {