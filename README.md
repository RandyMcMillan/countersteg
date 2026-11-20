# countersteg

Generative music steganography studio. A Markov–counterpoint hybrid engine composes
valid first-species polyphony; hidden payloads ride the *musical selection channel*
(which notes the generator chooses), so a composed score is also a ciphertext.

Derived from the randymcmillan gist corpus (Markov-Counterpoint.rs, HighlightStego.rs,
std_stego.rs, entropy_payload.rs, Xoroshiro128PlusPlus.rs, nist_800-90b.rs).

## Layout

- `crates/engine` — Markov chain + Fuxian first-species counterpoint composer, MIDI export
- `crates/stego` — selection-channel encode/decode over composer decision points
- `crates/entropy` — xoroshiro128++ keystream, Shannon entropy, health stats
- `crates/keys` — passphrase key schedule (SHA-256), pre-cipher layer
- `crates/cli` — `countersteg` binary: compose / embed / extract / stats

## Usage

```
countersteg compose  --seed 42 --bars 16 --out plain.mid
countersteg embed    --seed 42 --bars 16 --message "hello" --key pass --out stego.mid
countersteg extract  --in stego.mid --key pass
countersteg stats    --in stego.mid
```
