//! Known-answer tests: expected values are hardcoded, not computed at test
//! time, so a defect in both the implementation and the comparison crate
//! cannot cancel out. Vectors were captured from the RustCrypto `sha2` crate
//! (FIPS 180-4) and the reference `rand_xoshiro` generator.
//!
//! SHA-256 digests below are the canonical published FIPS 180-4 example
//! outputs (see csrc.nist.gov publications fips180-4).

use entropy::Xoroshiro128PlusPlus;
use keys::{derive_key, mac_tag, sha256};

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

// ---- key schedule / MAC known answers ----
// Captured from RustCrypto sha2 over the documented compositions
// (see crypto_vectors.rs for the live cross-checks).

const DK_EMPTY_0: &str =
    "bc245fee0dd2c0bf7ef20970c28d5e56bbdde4aec86dbbc66fb440af587caa33";
const DK_PW_1: &str =
    "6d2de82d962a9e9864fe615e31135a520286c6c2b3bc8d8d8db988faf7e512d8";
const DK_VECTOR: &str =
    "c9f49168df95aef0b3da15308c74dc3a7d6708d916808f5f02275ad400e16926";

#[test]
fn derive_key_known_answers() {
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
    assert_eq!(mac_tag("pw", 7, &data), 0x9f);
}

// ---- keystream known answer ----
// First 32 keystream bytes for passphrase "stream vector", seed 42, via
// keys::keystream's generator construction (from_seed_bytes(derive_key(..))).

const KS_STREAM_VECTOR_42: &str =
    "e905df0e1e82616f756df5887ce27b424912adcf8a9a95b02c17bc4a200f8181";

#[test]
fn keystream_known_answer() {
    let mut g = Xoroshiro128PlusPlus::from_seed_bytes(&derive_key("stream vector", 42));
    let bytes: Vec<u8> = (0..32).map(|_| g.next_byte()).collect();
    assert_eq!(hex(&bytes), KS_STREAM_VECTOR_42);
}

// ---- end-to-end pre-cipher known answer ----
// The exact keystream-XOR framing used by stego::embed's pre-cipher:
// ciphertext[i] = plaintext[i] XOR keystream_byte[i].

#[test]
fn keystream_xor_known_answers() {
    // ciphertext[i] = plaintext[i] XOR keystream[i] — hardcoded outputs,
    // so tampering with the keystream or the XOR path breaks these.
    let cases: &[(&[u8], &str, u64, &str)] = &[
        (
            b"known answer plaintext!",
            "ka key",
            99,
            "2929baa08f4e7add565d45c10f9209daff98acfd143f1e",
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            "fox",
            0,
            "2a150d5de970d44bd010efff42ea2dcfd5eedf444625056ba7ba46c82b9f458de8c87184372508dc997dda",
        ),
    ];
    for (msg, pass, seed, expect_ct) in cases {
        let mut g = Xoroshiro128PlusPlus::from_seed_bytes(&derive_key(pass, *seed));
        let mut ct = msg.to_vec();
        for b in ct.iter_mut() {
            *b ^= g.next_byte();
        }
        assert_eq!(hex(&ct), *expect_ct, "pass {pass:?} seed {seed}");
        // and the XOR path is symmetric: decrypting restores the plaintext
        let mut g = Xoroshiro128PlusPlus::from_seed_bytes(&derive_key(pass, *seed));
        for b in ct.iter_mut() {
            *b ^= g.next_byte();
        }
        assert_eq!(&ct, msg);
    }
}
