//! keys: passphrase key schedule (v2).
//! SHA-256("countersteg-v2" || passphrase || nonce_le64), iterated ~100k
//! rounds (PBKDF2-flavored stretching) -> 32-byte session key
//! -> SHA-256-CTR keystream (block i = SHA-256(key || le64(i))).
//! Self-contained SHA-256 (FIPS 180-4); zero dependencies.
//!
//! The v2 schedule replaces the v1 xoroshiro128++ keystream (a
//! non-cryptographic PRNG vulnerable to state recovery from known output)
//! and the 1-byte MAC (1/256 forgery odds). See MITIGATIONS.md (M2, M3).

/// SHA-256 digest of `parts`.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut msg: Vec<u8> = Vec::new();
    for p in parts {
        msg.extend_from_slice(p);
    }
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for j in 0..16 {
            w[j] = u32::from_be_bytes(chunk[j * 4..j * 4 + 4].try_into().unwrap());
        }
        for j in 16..64 {
            let s0 = w[j - 15].rotate_right(7) ^ w[j - 15].rotate_right(18) ^ (w[j - 15] >> 3);
            let s1 = w[j - 2].rotate_right(17) ^ w[j - 2].rotate_right(19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16]
                .wrapping_add(s0)
                .wrapping_add(w[j - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for j in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[j])
                .wrapping_add(w[j]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Key-stretching rounds applied on top of the initial digest. ~100k
/// iterated SHA-256 compressions make offline passphrase guessing cost
/// real work even though a single SHA-256 is cheap.
pub const STRETCH_ROUNDS: u32 = 100_000;

/// Derive a 32-byte session key from passphrase + nonce.
///
/// v2: initial digest SHA-256("countersteg-v2" || passphrase || nonce_le64)
/// is then fed through `STRETCH_ROUNDS` iterations of SHA-256(state).
pub fn derive_key(passphrase: &str, nonce: u64) -> [u8; 32] {
    let mut key = sha256(&[
        b"countersteg-v2",
        passphrase.as_bytes(),
        &nonce.to_le_bytes(),
    ]);
    for _ in 0..STRETCH_ROUNDS {
        key = sha256(&[&key]);
    }
    key
}

/// SHA-256-CTR keystream: block `i` is `SHA-256(key || le64(i))`, bytes
/// served sequentially. A proper stream cipher built from the existing
/// primitive — no PRNG state to recover.
pub struct Sha256Ctr {
    key: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    pos: usize,
}

impl Sha256Ctr {
    /// Start a keystream from an already-derived session key (avoids
    /// repeating the stretching when the caller derives once per operation).
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key, counter: 0, buf: [0; 32], pos: 32 }
    }

    fn new(key: [u8; 32]) -> Self {
        Self::from_key(key)
    }

    pub fn next_byte(&mut self) -> u8 {
        if self.pos == 32 {
            let mut block_input = Vec::with_capacity(40);
            block_input.extend_from_slice(&self.key);
            block_input.extend_from_slice(&self.counter.to_le_bytes());
            self.buf = sha256(&[&block_input]);
            self.counter = self.counter.wrapping_add(1);
            self.pos = 0;
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }
}

/// Keystream generator for the pre-cipher layer.
pub fn keystream(passphrase: &str, nonce: u64) -> Sha256Ctr {
    Sha256Ctr::new(derive_key(passphrase, nonce))
}

/// XOR `data` with the keystream derived from an already-derived key.
pub fn apply_keystream_with_key(data: &mut [u8], key: &[u8; 32]) {
    let mut ks = Sha256Ctr::from_key(*key);
    for b in data.iter_mut() {
        *b ^= ks.next_byte();
    }
}

/// XOR `data` with the keystream derived from passphrase + nonce.
pub fn apply_keystream(data: &mut [u8], passphrase: &str, nonce: u64) {
    apply_keystream_with_key(data, &derive_key(passphrase, nonce));
}

/// 16-byte MAC tag over the ciphertext from an already-derived key
/// (HMAC-style: SHA-256(key || data), truncated to 128 bits).
pub fn mac_tag_from_key(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let d = sha256(&[b"countersteg-mac-v2", key, data]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&d[..16]);
    tag
}

/// 16-byte MAC tag over the ciphertext (HMAC-style: SHA-256(key || data),
/// truncated to 128 bits). Wrong-key/tamper detection reliability
/// ~1 - 2^-128.
pub fn mac_tag(passphrase: &str, nonce: u64, data: &[u8]) -> [u8; 16] {
    mac_tag_from_key(&derive_key(passphrase, nonce), data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_kat() {
        // FIPS 180-4 known answer: "abc"
        let d = sha256(&[b"abc"]);
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn key_depends_on_seed_and_passphrase() {
        let a = derive_key("pw", 1);
        let b = derive_key("pw", 2);
        let c = derive_key("px", 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
