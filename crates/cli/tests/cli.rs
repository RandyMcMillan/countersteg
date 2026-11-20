//! End-to-end CLI tests: compose -> embed -> extract via MIDI files.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_countersteg"))
}

#[test]
fn compose_writes_midi() {
    let dir = std::env::temp_dir();
    let out = dir.join("countersteg-test-compose.mid");
    let status = bin()
        .args(["compose", "--seed", "1", "--bars", "8", "--out"])
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(&bytes[0..4], b"MThd");
    let _ = std::fs::remove_file(&out);
}

#[test]
fn embed_extract_roundtrip_via_midi() {
    let dir = std::env::temp_dir();
    let out = dir.join("countersteg-test-stego.mid");
    let status = bin()
        .args([
            "embed", "--seed", "7", "--message", "dead drop at noon", "--key", "pw", "--out",
        ])
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());

    let output = bin()
        .args(["extract", "--key", "pw", "--in"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "dead drop at noon");
    let _ = std::fs::remove_file(&out);
}

#[test]
fn extract_rejects_wrong_key() {
    let dir = std::env::temp_dir();
    let out = dir.join("countersteg-test-wrongkey.mid");
    bin()
        .args(["embed", "--message", "hidden", "--key", "right", "--out"])
        .arg(&out)
        .status()
        .unwrap();
    let status = bin()
        .args(["extract", "--key", "wrong", "--in"])
        .arg(&out)
        .status()
        .unwrap();
    assert!(!status.success());
    let _ = std::fs::remove_file(&out);
}
