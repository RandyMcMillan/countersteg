# countersteg

Generative music steganography studio. A Markov–counterpoint hybrid engine composes
valid first-species polyphony; hidden payloads ride the *musical selection channel*
(which notes the generator chooses), so a composed score is also a ciphertext.

Derived from the randymcmillan gist corpus (Markov-Counterpoint.rs, entropy_payload.rs,
Xoroshiro128PlusPlus.rs, nist_800-90b.rs, faux_hmac.rs).

## How it works

1. **Compose**: a weighted Markov random walk generates a cantus firmus; a
   first-species counterpoint voice is added under Fuxian rules (consonant
   intervals only, no parallel/hidden perfects, perfect consonances at start/end,
   imperfect penultimate, leap-follow rule).
2. **Embed**: at every decision point where `arity` rule-valid candidates exist,
   `floor(log2(arity))` payload bits pick the continuation. The channel is lossless
   because `2^n <= arity`, so the chosen index *is* the payload bits.
3. **Cipher first**: the message is framed as `[u8 length][keystream-XOR body][MAC tag]`
   (SHA-256 key schedule -> xoroshiro128++ keystream) before touching the channel,
   so the channel bitstream looks random.
4. **Extract**: candidate generation is replayed against the notes in the MIDI
   file; the index of each taken note recovers the bits. No seed file needed —
   the seed travels in the MIDI track-name meta event.

Capacity is ~2.8 bits per whole note (~0.35 bytes/note); `embed` auto-extends
the score until the payload fits.

## Layout

- `crates/engine` — composer, rules, dependency-free SMF read/write
- `crates/stego` — selection-channel encode/decode, bitstream framing
- `crates/entropy` — xoroshiro128++ keystream, Shannon entropy, uniformity
- `crates/keys` — SHA-256 key schedule, MAC tag
- `crates/cli` — `countersteg` binary
- `crates/wasm` — zero-dependency `wasm32-unknown-unknown` bindings (raw FFI,
  no wasm-bindgen): `compose_midi` / `embed_midi` / `extract_message`
- `web/` — browser studio UI (compose / embed / extract tabs) served by the
  GitHub Pages workflow

## WASM + web demo

```sh
rustup target add wasm32-unknown-unknown
cargo build --release -p countersteg-wasm --target wasm32-unknown-unknown
# -> target/wasm32-unknown-unknown/release/countersteg_wasm.wasm
```

Serve `web/` plus the `.wasm` from any static host, or merge `.github/workflows/pages.yml`
to let GitHub Actions build and publish the demo to GitHub Pages automatically
(the page loads `countersteg_wasm.wasm`, falling back to `countersteg_wasm.b64`).

## Usage

```sh
countersteg compose --seed 42 --bars 16 --out plain.mid
countersteg embed   --seed 42 --message "attack at dawn" --key s3cret --out stego.mid
countersteg extract --in stego.mid --key s3cret
countersteg stats   --in stego.mid
```

## Tests

```sh
cargo test --workspace   # 29 tests: rules, roundtrips, wrong-key, CLI e2e
```

## Roadmap (from the gist-corpus plan)

- M5: statistical distinguishability panel (NIST 800-90b battery over scores
  with/without payload)
- M6: SVG-filter delivery channel (HighlightStego.rs), HTML bundle
- M7: ~~WASM build + web UI~~ done (`crates/wasm` + `web/` + Pages workflow); desktop shell via wry/tauri remains
- Optional anchor: signet OP_RETURN timestamping + Sigma-protocol receipt
