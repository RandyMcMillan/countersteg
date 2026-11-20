//! Known-answer tests: expected values are hardcoded, not computed at test
//! time, so a defect in both the implementation and the comparison crate
//! cannot cancel out. Vectors were captured from real runs of the v2 key
//! schedule (see crypto_vectors.rs for live cross-checks against RustCrypto
//! sha2).
//!
//! SHA-256 digests below are the canonical published FIPS 180-4 example
//! outputs (see csrc.nist.gov publications fips180-4).

use keys::{apply_keystream, derive_key, keystream, mac_tag, sha256, STRETCH_ROUNDS};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- FIPS 180-4 example digests (published values) ----

const SHA256_EMPTY: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_ABC: &str =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SHA256_FIPS56: &str =
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
const SHA256_MILLION_A: &str =
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

#[test]
fn sha256_fips180_4_known_answers() {
    assert_eq!(hex(&sha256(&[b""])), SHA256_EMPTY);
    assert_eq!(hex(&sha256(&[b"abc"])), SHA256_ABC);
    assert_eq!(
        hex(&sha256(&[b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"])),
        SHA256_FIPS56
    );
    let million_a = vec![b'a'; 1_000_000];
    assert_eq!(hex(&sha256(&[&million_a])), SHA256_MILLION_A);
}

// ---- v2 key schedule known answers ----
// derive_key = SHA-256("countersteg-v2" || pass || nonce_le64) iterated
// SHA-256(state) for STRETCH_ROUNDS rounds. Captured from real runs.

const DK_EMPTY_0: &str =
    "989536a4043ae983fe19f4e035d2a7d1b6f1b7d2e22f3d2fe81859fdfdba0bdb";
const DK_PW_1: &str =
    "f9f726ccd16cd3aac8113e0495578b04e99bf6b2066f06654da07c54a577bb3b";
const DK_VECTOR: &str =
    "858483fa2f7b7b828d2d8fe5b44c36275164e801cb3fe7722b04d927368b8006";

#[test]
fn derive_key_known_answers() {
    assert_eq!(STRETCH_ROUNDS, 100_000);
    assert_eq!(hex(&derive_key("", 0)), DK_EMPTY_0);
    assert_eq!(hex(&derive_key("pw", 1)), DK_PW_1);
    assert_eq!(hex(&derive_key("countersteg vector test", 0x1122334455667788)), DK_VECTOR);
}

#[test]
fn mac_tag_known_answer() {
    // data = pseudo_msg(64) as defined in crypto_vectors.rs
    let data: Vec<u8> = (0..64u64)
        .map(|i| ((i.wrapping_mul(2654435761) >> 13) & 0xff) as u8)
        .collect();
    assert_eq!(
        hex(&mac_tag("pw", 7, &data)),
        "3f801395caa965f0d04f7ee1a381b342"
    );
}

// ---- SHA-256-CTR keystream known answer ----
// First 32 keystream bytes for passphrase "stream vector", nonce 42, via
// keys::keystream's construction (block i = SHA-256(key || le64(i))).

const KS_STREAM_VECTOR_42: &str =
    "7a235db24ca5339370a192984fff047b0eaa32b0daae65d6db4a4647d625a471";

#[test]
fn keystream_known_answer() {
    let mut g = keystream("stream vector", 42);
    let bytes: Vec<u8> = (0..32).map(|_| g.next_byte()).collect();
    assert_eq!(hex(&bytes), KS_STREAM_VECTOR_42);
}

// ---- end-to-end pre-cipher known answer ----
// The exact keystream-XOR used by stego::embed's pre-cipher:
// ciphertext[i] = plaintext[i] XOR keystream_byte[i].

#[test]
fn keystream_xor_known_answers() {
    let cases: &[(&[u8], &str, u64, &str)] = &[
        (
            b"known answer plaintext!",
            "ka key",
            99,
            "913649949d9cda9651fd8b1f1448c249a94211a9019b39",
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            "fox",
            0,
            "afc5f80fdf95db215273935364394d3aee64c7266a9ddfcfd22e25aed3c5b1ddcc1f9447ca02843c6cb480",
        ),
    ];
    for (msg, pass, nonce, expect_ct) in cases {
        let mut ct = msg.to_vec();
        apply_keystream(&mut ct, pass, *nonce);
        assert_eq!(hex(&ct), *expect_ct, "pass {pass:?} nonce {nonce}");
        // and the XOR path is symmetric: decrypting restores the plaintext
        apply_keystream(&mut ct, pass, *nonce);
        assert_eq!(&ct, msg);
    }
}
