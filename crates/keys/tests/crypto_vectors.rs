//! Cross-validation of the hand-rolled SHA-256 and its compositions against
//! the RustCrypto `sha2` crate (FIPS 180-4 implementation). Dev-dependencies
//! only — the library itself stays zero-dependency.

use keys::{derive_key, mac_tag, sha256};
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
    for (pass, seed) in cases {
        let mut h = Sha256::new();
        h.update(b"countersteg-v1");
        h.update(pass.as_bytes());
        h.update(seed.to_le_bytes());
        assert_eq!(derive_key(pass, *seed).as_slice(), h.finalize().as_slice(), "pass {pass:?}");
    }
}

#[test]
fn mac_tag_matches_sha2_composition() {
    let data = pseudo_msg(64);
    let key = derive_key("pw", 7);
    let mut h = Sha256::new();
    h.update(b"countersteg-mac");
    h.update(key);
    h.update(&data);
    assert_eq!(mac_tag("pw", 7, &data), h.finalize()[0]);
}
