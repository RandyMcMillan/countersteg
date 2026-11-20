//! Cross-validation of the hand-rolled SHA-256 and the key/MAC compositions
//! against the RustCrypto `sha2` crate (FIPS 180-4 reference implementation).
//!
//! Dev-dependency only: `sha2` is not part of the library's public dependency
//! graph and never reaches downstream consumers.

use countersteg_keys::{derive_key, mac_tag, sha256};
use sha2::{Digest, Sha256};

/// Deterministic pseudo-message so tests run fast without external fixtures.
fn pseudo_msg(len: usize) -> Vec<u8> {
    // Simple LCG pattern, fixed seed: same input length -> same bytes every run.
    let mut out = Vec::with_capacity(len);
    let mut s: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..len {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((s >> 33) as u8);
    }
    out
}

fn ref_sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// NIST / FIPS 180-4 example vectors, including the classic 1,000,000-'a'
/// long-message vector (generated programmatically to keep the test fast).
#[test]
fn sha256_matches_sha2_nist_vectors() {
    let cases: &[(&[u8], &str)] = &[
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (msg, hex) in cases {
        assert_eq!(hex::encode(sha256(msg)), *hex, "sha256({msg:?})");
    }
    // 1,000,000 repetitions of 'a' — the standard long-message test.
    let million_a = vec![b'a'; 1_000_000];
    assert_eq!(
        hex::encode(sha256(&million_a)),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
}

/// Exercise every padding boundary: message lengths 0..=300 plus a few large
/// ones, so the block-compression padding paths are all compared against the
/// trusted implementation.
#[test]
fn sha256_matches_sha2_all_boundary_lengths() {
    let mut lens: Vec<usize> = (0..=300).collect();
    lens.extend([511, 512, 513, 1000, 4096]);
    for len in lens {
        let msg = pseudo_msg(len);
        assert_eq!(
            sha256(&msg),
            ref_sha256(&msg),
            "sha256 mismatch at message length {len}"
        );
    }
}

/// `derive_key` must equal SHA-256 over the exact documented composition.
#[test]
fn derive_key_matches_sha2_composition() {
    let cases: &[(&str, u64)] = &[
        ("passphrase", 0),
        ("hunter2", 42),
        ("", 0),
        ("correct horse battery staple", u64::MAX),
        ("pässphräse — unicode ✓", 0xdead_beef_cafe_f00d),
    ];
    for (pass, seed) in cases {
        let mut h = Sha256::new();
        h.update(b"countersteg-v1");
        h.update(pass.as_bytes());
        h.update(seed.to_le_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(derive_key(pass, *seed), expected, "derive_key({pass:?}, {seed})");
    }
}

/// `mac_tag` must equal the first byte of SHA-256 over the documented MAC
/// composition.
#[test]
fn mac_tag_matches_sha2_composition() {
    let key = derive_key("mac test key", 7);
    let data = pseudo_msg(64);
    let mut h = Sha256::new();
    h.update(b"countersteg-mac");
    h.update(key);
    h.update(&data);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(mac_tag(&key, &data), expected[0]);
}

/// Tiny local hex helper so the test file has no extra dev-deps.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }
}
