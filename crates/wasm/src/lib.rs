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
