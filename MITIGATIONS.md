# Mitigation Plan

Threat model: Kerckhoffs — the algorithm and the SMF files are public; only
the passphrase is secret. Attacks are ranked by severity; each maps to a
mitigation with a phase. Phases are ordered so that P0 removes the fatal
flaws, P1 raises attack cost, P2 closes statistical holes, P3 adds robustness.

## Attacks

- **A1 — Cover recomputation (fatal).** Embed writes the seed into the SMF
  track name (`seed:N`), and `engine::compose(seed, len)` is fully
  deterministic. A warden re-runs the generator, diffs against the embedded
  file, and every steered decision lights up: exact ciphertext recovery, no
  statistics needed.
- **A2 — Known-plaintext keystream exposure.** Framing is
  `[len][ciphertext][1-byte MAC][zero padding]`. Padding bits are steered by
  raw keystream (0 XOR keystream), giving the warden long known-keystream
  runs. The keystream is Xoroshiro128++ — a non-cryptographic 128-bit PRNG
  leaking 8 bits per output word — so state recovery from a few hundred known
  bytes is feasible.
- **A3 — Padding signature (statistical, no seed needed).** `build_bitstream`
  steers *every* decision, including padding: value 0 selects candidate
  `0 % arity == 0` at every post-framing decision. The tail of every embedded
  file picks candidate 0, which natural generation (PRNG chooser) essentially
  never does. A chi-square test over late-path choices flags embedded files
  without any key material.
- **A4 — Two-time pad.** Same passphrase + seed reuses the keystream. With
  covers recomputable (A1), the warden XORs two bitstreams and reads the
  message XOR. The published seed makes reuse trivially detectable and
  inducible (a chosen seed handed to the sender).
- **A5 — Offline passphrase brute force.** Wrong-passphrase rejection is
  cheap: the 8-bit MAC plus padding-zero checks give many independent filters
  per guess. Weak passphrases fall fast.
- **A6 — Weak integrity.** The MAC is one byte (`sha256(...)[0]`); random
  tampering passes with probability 1/256. An active warden corrupts or
  forges messages cheaply; there is no error correction.
- **A7 — Metadata flagging.** The `seed:N` track name self-identifies
  countersteg output. Standard MIDI steganalysis (delta-time/velocity
  statistics) also targets substitution-style schemes.

## Mitigations

### P0 — design fixes (crates `keys`, `stego`, `wasm`, web, CLI)

- **M1 (A1, A4, A7): remove the seed from the cover entirely.**
  - Framing becomes `[8-byte nonce][u8 len][ciphertext][16-byte tag]`.
  - The nonce is random per message and travels inside the framing, readable
    by the decoder but meaningless to the warden.
  - Key derivation moves to the nonce: `keystream(passphrase, nonce_u64)`.
    Same passphrase, different message ⇒ different keystream: two-time pad
    gone even with lazy passphrase reuse.
  - `embed_midi` no longer writes `seed:N` into the track name; `extract`
    parses the nonce from the bitstream instead of the track name. The web
    Extract tab drops its dependence on track-name metadata.
  - Compose keeps publishing its seed — it is not stego, and the demo's
    determinism story (COMPOSE.md) is unchanged.
- **M2 (A2): replace the PRNG keystream with SHA-256-CTR.**
  `keystream_block(key, i) = sha256(key || le64(i))`. Keeps the zero-dependency
  guarantee (SHA-256 is already in `keys`), removes PRNG state recovery
  entirely, and gives a proper stream cipher.
- **M3 (A5, A6): 16-byte MAC + key stretching.**
  - `mac_tag` returns `sha256("countersteg-mac-v2" || derive_key(...) ||
    data)[..16]` — 128-bit forgery resistance.
  - `derive_key` iterates SHA-256 ~100k times (PBKDF2-flavored stretching with
    existing primitives) so offline guessing costs real work.
- **M4 (A3, A2): kill the padding signature.**
  - Fill padding by continuing the keystream (decrypts to random), never
    zeros. The decoder stops after the tag, so padding content is free.
  - After framing bits are exhausted, `PayloadChooser` falls back to a PRNG
    chooser (seeded from key material) for all remaining decisions. The tail
    of an embedded file then matches the natural generator's distribution.
  - Framing overhead grows from 2 to 25 bytes; the 255-byte message cap and
    capacity-extension logic in `embed` are unaffected.

Breaking changes: known-answer vectors in `crates/keys/tests` and
`crates/stego` regenerate; cross-validation tests against RustCrypto/rand_xoshiro
dev-deps are unaffected (they test SHA-256 and xoroshiro as primitives). The
WASM FFI signatures for `embed_midi`/`extract_message` change; `web/app.js`
and the CLI follow.

### P1 — cost-raising and hygiene

- **M5 (A5):** document passphrase entropy requirements (>= 80 bits) in README
  and the web UI; refuse obviously weak passphrases in the CLI (length +
  distinct-character checks).
- **M6 (A7):** scrub remaining metadata markers: `write_smf_named` gains a
  no-name mode for embed output; no countersteg-identifying strings in
  embedded files.

### P2 — statistical hardening (implemented)

- **M7 (A3 residual): distribution-preserving selection — IMPLEMENTED
  (`crates/stego/src/ac.rs`).** The v2 chunk chooser steered decisions onto
  `2^n` of `arity` candidates (`v % arity == v` since `2^n <= arity`) —
  candidate indices `>= 2^n` were never taken at payload decisions, a bias
  against any warden modeling the engine's choice distribution. Replaced
  with mixed-radix selection: the framed payload is one big-endian integer
  and each decision pops one digit `s = x mod arity`, so digits of the
  encrypted + MACed payload are uniform over the full arity at every steered
  decision. Capacity is the product of arities (`floor(sum(log2(arity)))`
  bits); `embed` extends the score until capacity covers the region and a
  full in-process extraction reproduces the message.
  - Payload region layout: `0x01 sentinel || key-derived IV(16) || nonce(8)
    || len(1) || ciphertext || MAC tag(16) || 0x01 trailer`. The key-derived
    IV authenticates the framing boundary before the claimed length is
    trusted; both 0x01 markers keep byte re-serialization stable.
  - Why not a binary arithmetic coder: a binary AC with E1/E2/E3
    renormalization is not exactly invertible in the embed direction — the
    E3 underflow case defers bits and re-emits them as complements of the
    resolving bit, so `encode(decode(x)) != x` (verified empirically: the
    framing MAC failed on ~every short message). Mixed radix over the choice
    arities is a pure bijection — no renormalization, exact replay.
- **M8: self-steganalysis CI test — IMPLEMENTED (`crates/stego` tests).**
  `self_steganalysis_distribution_matches_natural` embeds with 24 fixed
  seeds and compares the per-arity choice distribution (total variation)
  against the natural `compose` baseline — under 0.15 for every arity, the
  same threshold a warden would use. `payload_choices_use_full_arity`
  asserts every arity bucket sees its full candidate range across 12
  nonces. M7 is done when the warden's own test cannot separate embedded
  from natural.

### P3 — robustness (optional)

- **M9 (A6 residual):** error correction for the active-warden case — simple
  3x repetition coding first (zero-dep), Reed-Solomon later if capacity
  budget allows.
- **M10:** multi-file consensus — split a message across several scores so no
  single file carries the whole plaintext.

## Prior art anchoring

Selection-channel theory: Fridrich, Goljan & Soukal, "Writing on wet paper"
(IEEE TSP 2005). Generative stego with distribution-preserving encoding:
generative linguistic steganography (Markov + arithmetic-coding line, 2016–
2022) and Su et al., "Message-driven generative music steganography using
MIDI-GAN" (IEEE Trans. 2024) — the closest published system; M7/M8 are the
positioning work against it.
