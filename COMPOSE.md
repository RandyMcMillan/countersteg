# Compose Panel

The Compose tab of the web demo (`web/index.html` + `web/app.js`, WASM build of
the same Rust engine as the CLI) demonstrates the **control group** of the
steganography system:

- The engine produces genuine Fuxian-species counterpoint on its own, with no
  payload involved — a cover generator that already sounds like music, so an
  embedded file does not change the character of the output.
- It exposes the decision points that Embed later steers: at each rule-valid
  note choice, the generator picks one candidate; the stego layer replaces that
  free choice with a payload-driven one. Compose shows what those choices look
  like when left to chance.
- It demonstrates determinism: the same seed and length reproduce the exact
  same score on every device, because the browser WASM and the CLI run
  byte-identical engine code.
- Audition/download round-trip with the CLI: a `.mid` produced by Compose in
  the browser can be fed to the CLI's extract/compose tooling and vice versa.

## What the seed does

The seed is the generator's only randomness source.

- `compose(seed, len)` is fully deterministic: same seed + same length/bars
  produce identical MIDI every time.
- Mechanically, the Compose tab's seed field maps to
  `compose_midi(BigInt(seed), bars)` in `web/app.js`, which calls
  `engine::compose(seed, len)` in `crates/wasm/src/lib.rs`. The engine turns
  the seed into `Xoroshiro128PlusPlus` state (all-zero fixup to the
  golden-ratio constant, two warmup outputs discarded) and uses that PRNG to
  pick among rule-valid counterpoint choices whenever no stego payload is
  steering.
- The seed is written into the SMF track name as `seed:N`
  (`write_smf_named(..., Some(&format!("seed:{seed}")))`); for Compose output
  this is a public demo convenience, not a secret. Embedded files (Embed tab
  / CLI `embed`) write no track name at all: a random nonce travels inside
  the framing and keys the keystream, so only the passphrase must be shared
  out of band.
- Contrast with Embed: the same deterministic engine, but note choices are
  driven by the keystream derived from passphrase + nonce (XORed with the
  message, then the resulting bitstream — not the raw PRNG — chooses the
  notes), and the tail past the message is driven by the engine's own PRNG
  rather than zero padding.

CLI equivalent: `countersteg compose --seed <N> --bars <N>`.
