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

### P0 — design fixes (crates `keys`, `stego`, `wasm`, web, CLI) — IMPLEMENTED

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

### P1 — cost-raising and hygiene — IMPLEMENTED

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

### P3 — robustness (implemented)

- **M9 (A6 residual): error correction — IMPLEMENTED (`embed_with_ecc`).**
  The framed region is triplicated as `[0x02][region x3]`; extraction
  majority-votes the three copies, correcting any single-byte corruption of
  the payload integer before the MAC is checked. The 0x02 marker is detected
  on decode, so ECC and non-ECC files interoperate transparently. Costs 3x
  capacity — the message cap drops to 64 bytes to keep the embed extension
  budget sufficient. Reed-Solomon remains a later option if the capacity
  budget grows.
- **M10: multi-file consensus — IMPLEMENTED (`embed_split` / `extract_join`).**
  A message is sharded across `count` compositions; each shard embeds
  `[index][total][len][chunk]` through the normal single-file path (per-shard
  nonce `base + i`), so no single file carries the whole plaintext and the
  255-byte cap no longer bounds the message. Reassembly requires every shard
  exactly once with consistent totals — a withheld or substituted shard is
  detectable.

## Prior art anchoring

### Theory lineage

- **Wet paper / syndrome-trellis codes (Fridrich, Goljan & Soukal, "Writing
  on wet paper", IEEE TSP 2005; Fridrich & Soukal STC 2006).** The
  theoretical foundation of selection-channel stego: the sender controls
  only the *wet* subset of coefficients and the embedding minimizes
  distortion over that subset. Countersteg differs in a load-bearing way:
  the wet paper model assumes a cover object exists and the warden may
  compare against it. Here the cover is *generated by the payload's own
  generator* — there is no original to diff against (A1 was exactly that
  hole), so the warden's only handle is distribution testing, which is
  what M7/M8 address.
- **Generative linguistic steganography (Markov + Huffman/arithmetic-coding
  line: Yang et al. 2018 arXiv:1811.04720 "RNN-Stega"; Ziegler et al.
  2019 neural AC; through Zhang et al. 2021 "Provably Secure Generative
  Linguistic Steganography").** Establishes that *any*
  distribution-preserving selector over a language model is theoretically
  secure (the model's own output distribution is the stego distribution).
  Countersteg is the music-domain instance of this line, with two
  departures: (1) the channel is not a Markov token stream but a
  rule-constrained first-species counterpoint decision tree (Fux rules via
  the engine's `is_consonant`/voice-leading legality — the "candidates" a
  digit selects among are only the *legal* continuations, so correctness
  of the surface music is structural, not statistical); (2) M7 replaced
  the classic binary arithmetic coder with an exact mixed-radix bijection
  after measuring that E1/E2/E3 renormalization is not exactly invertible
  in the embed direction for this framing (the MAC failed on nearly every
  short message). Mixed radix trades AC's asymptotic optimality for exact
  replay — the right trade when the tag must survive encode→decode.
- **Su et al., "Message-Driven Generative Music Steganography Using
  MIDI-GAN" (IEEE Trans. Dependable Secure Comput. 21(6), 2024, doi
  10.1109/TDSC.2024.3372139).** The closest published system: a GAN
  generator synthesizes a stego MIDI file from the message itself
  (message-driven generative, same top-level family as countersteg),
  with a discriminator pushing the output toward authentic-MIDI
  statistics, an ECC stage, and a CNN extractor. The structural
  difference is *where the security argument lives*. MIDI-GAN's
  undetectability is an empirical, learned property: the GAN must match
  the authentic MIDI distribution well enough to fool deep-learning
  steganalyzers, and reviews of the system note sensitivity to parameter
  choices and low capacity. Countersteg's undetectability is exact by
  construction: the output distribution is the generator's own (M7
  mixed-radix bijection + M8 CI total-variation < 0.15), legality of
  the surface music is enforced by the counterpoint rules rather than
  learned, and the embed→extract transform is a proven bijection, not a
  trained extractor that must be re-validated per model.

### Where countersteg sits

The system is best described as **generative selection-channel stego over
a rule-constrained symbolic generator, with exact mixed-radix channel
coding and self-steganalysis CI**. It inherits the wet-paper/linguistic
line's security argument (output distribution = model distribution) but
implements it without a statistical model of the surface at all: legality
of the music is enforced by the counterpoint rules, uniformity of the
payload is enforced by the bijection, and the composition is checked
against the natural generator in CI (M8). MIDI-GAN shows the neural
alternative pays for its flexibility with a learned distribution match to
defend (discriminator + extractor networks whose empirical guarantees
must be re-validated per dataset) and reports low capacity with parameter
sensitivity; the symbolic line pays with a much smaller channel (255
bytes/file, or 64 with ECC) and a grammar-fixed surface style.
