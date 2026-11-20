//! Cross-validation of the hand-rolled SHA-256 and its compositions against
//! the RustCrypto `sha2` crate (FIPS 180-4 implementation). Dev-dependencies
//! only — the library itself stays zero-dependency.

use keys::{derive_key, keystream, mac_tag, sha256, STRETCH_ROUNDS};
use sha2::{Digest, Sha256};

fn pseudo_msg(len: usize) -> Vec<u8> {
    // deterministic non-uniform input (LCG-ish byte pattern)
    (0..len as u64)
        .map(|i| ((i.wrapping_mul(2654435761) >> 13) & 0xff) as u8)
        .collect()
}

#[test]
fn sha256_matches_sha2_nist_vectors() {
    let million_a = vec![b'a'; 1_000_000];
    let cases: &[&[u8]] = &[
        b"",
        b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        &million_a,
    ];
    for msg in cases {
        let ours = sha256(&[msg]);
        let theirs = Sha256::digest(msg);
        assert_eq!(ours.as_slice(), theirs.as_slice(), "NIST vector len {}", msg.len());
    }
}

#[test]
fn sha256_matches_sha2_all_boundary_lengths() {
    // exercise padding paths: exact blocks, 55/56/63/64/119/120-byte edges
    for len in (0..=300usize).chain([511, 512, 513, 1000, 4096]) {
        let msg = pseudo_msg(len);
        let ours = sha256(&[&msg]);
        let theirs = Sha256::digest(&msg);
        assert_eq!(ours.as_slice(), theirs.as_slice(), "len {len}");
    }
}

#[test]
fn derive_key_matches_sha2_composition() {
    let cases: &[(&str, u64)] = &[
        ("", 0),
        ("pw", 1),
        ("s3cret", u64::MAX),
        ("üñïçødé", 42),
        ("a much longer passphrase with spaces and UPPERlower123", 0xdead_beef),
    ];
    for (pass, nonce) in cases {
        // v2 schedule: initial digest, then STRETCH_ROUNDS iterated SHA-256.
        let mut h = Sha256::new();
        h.update(b"countersteg-v2");
        h.update(pass.as_bytes());
        h.update(nonce.to_le_bytes());
        let mut expect = h.finalize();
        for _ in 0..STRETCH_ROUNDS {
            expect = Sha256::digest(&expect);
        }
        assert_eq!(derive_key(pass, *nonce).as_slice(), expect.as_slice(), "pass {pass:?}");
    }
}

#[test]
fn mac_tag_matches_sha2_composition() {
    let data = pseudo_msg(64);
    // v2 tag: first 16 bytes of SHA-256("countersteg-mac-v2" || key || data)
    let mut h = Sha256::new();
    h.update(b"countersteg-mac-v2");
    h.update(derive_key("pw", 7));
    h.update(&data);
    let expect = h.finalize();
    assert_eq!(mac_tag("pw", 7, &data), expect[..16]);
}

#[test]
fn keystream_matches_sha2_ctr_construction() {
    // block i = SHA-256(key || le64(i)); the stream concatenates block bytes.
    let key = derive_key("stream vector", 42);
    let mut g = keystream("stream vector", 42);
    let mut ours = Vec::new();
    for _ in 0..96 {
        ours.push(g.next_byte());
    }
    let mut expect = Vec::new();
    for i in 0..3u64 {
        let mut h = Sha256::new();
        h.update(key);
        h.update(i.to_le_bytes());
        expect.extend_from_slice(&h.finalize());
    }
    assert_eq!(ours, expect);
}
