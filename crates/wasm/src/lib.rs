//! countersteg-wasm: zero-dependency WASM bindings (raw FFI, no wasm-bindgen).
//!
//! The module imports nothing and works on `wasm32-unknown-unknown`.
//! JS passes input bytes via `alloc` + wasm memory, calls an operation, and
//! reads the result through `output_ptr` / `output_len`. On failure the
//! operations return 1 and the output holds the error message (`is_error`).
//!
//! Single-threaded model: the output buffer is a plain `static mut`.
#![allow(static_mut_refs)]

use std::slice;

static mut OUTPUT: Vec<u8> = Vec::new();
static mut FAILED: bool = false;

/// Allocate `len` bytes in wasm memory for JS to write into.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

/// Free a buffer previously returned by `alloc` with the same `len`.
#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe { drop(Vec::from_raw_parts(ptr, 0, len)) };
    }
}

fn ok(bytes: Vec<u8>) -> i32 {
    unsafe {
        OUTPUT = bytes;
        FAILED = false;
    }
    0
}

fn fail(message: impl Into<String>) -> i32 {
    unsafe {
        OUTPUT = message.into().into_bytes();
        FAILED = true;
    }
    1
}

unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() {
        &[]
    } else {
        slice::from_raw_parts(ptr, len)
    }
}

unsafe fn input_string(ptr: *const u8, len: usize) -> String {
    String::from_utf8_lossy(input(ptr, len)).into_owned()
}

fn cf_cp_from_midi(data: &engine::SmfData) -> Result<(Vec<engine::Note>, Vec<engine::Note>), String> {
    let cf: Option<Vec<engine::Note>> = data.cf.iter().map(|&m| engine::Note::from_midi(m)).collect();
    let cp: Option<Vec<engine::Note>> = data.cp.iter().map(|&m| engine::Note::from_midi(m)).collect();
    match (cf, cp) {
        (Some(a), Some(b)) => Ok((a, b)),
        _ => Err("non-diatonic note in MIDI".into()),
    }
}

/// Compose a plain piece. On success returns 0 and OUTPUT holds SMF bytes.
#[no_mangle]
pub extern "C" fn compose_midi(seed: u64, len: usize) -> i32 {
    let comp = engine::compose(seed, len.max(4));
    ok(engine::write_smf_named(&comp, Some(&format!("seed:{seed}"))))
}

/// Embed a message. On success returns 0 and OUTPUT holds SMF bytes
/// (seed carried in the track-name meta event).
#[no_mangle]
pub extern "C" fn embed_midi(
    msg_ptr: *const u8,
    msg_len: usize,
    pass_ptr: *const u8,
    pass_len: usize,
    seed: u64,
    min_len: usize,
) -> i32 {
    let (message, passphrase) = unsafe { (input(msg_ptr, msg_len), input_string(pass_ptr, pass_len)) };
    match stego::embed(message, &passphrase, seed, min_len.max(4)) {
        Ok((comp, _)) => ok(engine::write_smf_named(&comp, Some(&format!("seed:{seed}")))),
        Err(e) => fail(e.to_string()),
    }
}

/// Extract a message from SMF bytes. On success returns 0 and OUTPUT holds
/// the plaintext message.
#[no_mangle]
pub extern "C" fn extract_message(
    midi_ptr: *const u8,
    midi_len: usize,
    pass_ptr: *const u8,
    pass_len: usize,
) -> i32 {
    let (bytes, passphrase) = unsafe { (input(midi_ptr, midi_len), input_string(pass_ptr, pass_len)) };
    let data = match engine::read_smf(bytes) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let seed = match data
        .track_name
        .as_deref()
        .and_then(|n| n.strip_prefix("seed:"))
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(s) => s,
        None => return fail("no seed found in MIDI track name"),
    };
    let (cf, cp) = match cf_cp_from_midi(&data) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    match stego::extract(&cf, &cp, &passphrase, seed) {
        Ok(msg) => ok(msg),
        Err(e) => fail(e.to_string()),
    }
}

/// Pointer to the last result (SMF bytes, message bytes, or error text).
#[no_mangle]
pub extern "C" fn output_ptr() -> *const u8 {
    unsafe { OUTPUT.as_ptr() }
}

/// Length of the last result in bytes.
#[no_mangle]
pub extern "C" fn output_len() -> usize {
    unsafe { OUTPUT.len() }
}

/// 1 if the last call failed (OUTPUT holds the error message).
#[no_mangle]
pub extern "C" fn is_error() -> i32 {
    unsafe { FAILED as i32 }
}

// --- Built-in player: render SMF to mono f32 PCM (little-endian) ---

/// Tempo and timing constants matching `engine::midi::write_smf_named`
/// (500000 µs per quarter, 480 ticks per quarter, whole notes).
const TEMPO_US: u32 = 500_000;
const TPQ: u32 = 480;

/// Add one synthesized note into `buf` at `start` (sample index).
fn synth_note(buf: &mut [f32], start: usize, dur: usize, midi: u8, voice: u8, sr: f64) {
    let freq = 440.0 * 2f64.powf((midi as f64 - 69.0) / 12.0);
    let amp = if voice == 0 { 0.30 } else { 0.20 };
    let attack = (0.015 * sr) as usize;
    let release = (0.12 * sr) as usize;
    let end = (start + dur + release).min(buf.len());
    for i in start..end {
        let age = i - start;
        let env = if age < attack {
            age as f64 / attack as f64
        } else if age > dur {
            (1.0 - (age - dur) as f64 / release as f64).max(0.0)
        } else {
            1.0
        };
        let t = age as f64 / sr;
        let phase = freq * t;
        // CF (voice 0): triangle, piano-ish. CP (voice 1): band-limited saw.
        let v = if voice == 0 {
            let x = phase - (phase + 0.5).floor(); // -0.5..0.5
            4.0 * x.abs() - 1.0
        } else {
            let mut s = 0.0;
            for k in 1..=4 {
                s += (2.0 * std::f64::consts::PI * k as f64 * phase).sin() / k as f64;
            }
            s * 0.55
        };
        buf[i] = (buf[i] as f64 + amp * env * v) as f32;
    }
}

/// Render a countersteg SMF to mono f32 PCM at `sample_rate` Hz.
/// On success returns 0 and OUTPUT holds `4 * n` little-endian f32 bytes.
#[no_mangle]
pub extern "C" fn render_midi(midi_ptr: *const u8, midi_len: usize, sample_rate: u32) -> i32 {
    let bytes = unsafe { input(midi_ptr, midi_len) };
    let data = match engine::read_smf(bytes) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let (cf, cp) = match cf_cp_from_midi(&data) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let sr = (sample_rate.clamp(4_000, 192_000)) as f64;
    let spb = TEMPO_US as f64 / 1e6 / TPQ as f64; // seconds per tick
    let note_ticks = engine::TICKS_PER_NOTE as f64;
    let total = cf.len().max(cp.len()) as f64 * note_ticks * spb;
    let tail = 0.5; // ring-out
    let n = (total * sr) as usize + (tail * sr) as usize;
    let mut buf = vec![0f32; n];
    let note_samples = (note_ticks * spb * sr) as usize;
    for (i, note) in cf.iter().enumerate() {
        synth_note(&mut buf, (i as f64 * note_ticks * spb * sr) as usize, note_samples, note.midi(), 0, sr);
    }
    for (i, note) in cp.iter().enumerate() {
        synth_note(&mut buf, (i as f64 * note_ticks * spb * sr) as usize, note_samples, note.midi(), 1, sr);
    }
    // soft clip to [-1, 1]
    for s in buf.iter_mut() {
        *s = s.tanh();
    }
    let mut out = Vec::with_capacity(buf.len() * 4);
    for s in buf {
        out.extend_from_slice(&s.to_le_bytes());
    }
    ok(out)
}
