//! countersteg CLI: compose / embed / extract / stats.

use std::process::ExitCode;

const NAMES: [&str; 7] = ["C", "D", "E", "F", "G", "A", "B"];

fn note_name(midi: u8) -> String {
    let pos = midi as i16 - 60;
    let octave = pos.div_euclid(12);
    let offset = pos.rem_euclid(12);
    let degree = engine::theory::MAJOR_SCALE
        .iter()
        .position(|&s| s as i16 == offset)
        .unwrap_or(0);
    format!("{}{}", NAMES[degree], octave + 4)
}

fn print_score(cf: &[engine::Note], cp: &[engine::Note]) {
    if cp.len() == 2 * cf.len() {
        // Second species: two CP beats per position.
        println!("{:>4} {:>6} {:>8} {:>6}", "pos", "cf", "cp-down", "cp-up");
        for i in 0..cf.len() {
            println!(
                "{:>4} {:>6} {:>8} {:>6}",
                i,
                note_name(cf[i].midi()),
                note_name(cp[2 * i].midi()),
                note_name(cp[2 * i + 1].midi())
            );
        }
    } else {
        println!("{:>4} {:>6} {:>6}", "pos", "cf", "cp");
        for i in 0..cf.len() {
            println!(
                "{:>4} {:>6} {:>6}",
                i,
                note_name(cf[i].midi()),
                note_name(cp[i].midi())
            );
        }
    }
}

fn parse_species(args: &[String]) -> Option<stego::Species> {
    match opt(args, "--species") {
        None => Some(stego::Species::First), // no default swap, ever
        Some("1") => Some(stego::Species::First),
        Some("2") => Some(stego::Species::Second),
        Some(other) => {
            eprintln!("--species must be 1 or 2, got {other:?}");
            None
        }
    }
}

fn parse_seed(s: &str) -> u64 {
    s.parse().expect("seed must be a u64")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: countersteg <compose|embed|extract|stats> [options]");
        return ExitCode::from(2);
    }
    match args[1].as_str() {
        "compose" => cmd_compose(&args[2..]),
        "embed" => cmd_embed(&args[2..]),
        "extract" => cmd_extract(&args[2..]),
        "stats" => cmd_stats(&args[2..]),
        other => {
            eprintln!("unknown command {other:?}");
            ExitCode::from(2)
        }
    }
}

fn opt<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Why a passphrase is too weak to embed with, or None if acceptable.
/// MITIGATIONS.md M5: the 100k-round stretch slows offline guessing but
/// cannot stop it — passphrase entropy is the only real defense. This is a
/// floor, not a strength meter: 12+ chars with 6+ distinct characters.
fn passphrase_weakness(p: &str) -> Option<&'static str> {
    let len = p.chars().count();
    let unique = p.chars().collect::<std::collections::BTreeSet<_>>().len();
    if len < 12 {
        Some("shorter than 12 characters")
    } else if unique < 6 {
        Some("fewer than 6 distinct characters")
    } else {
        None
    }
}

fn cmd_compose(args: &[String]) -> ExitCode {
    let seed = opt(args, "--seed").map(parse_seed).unwrap_or(0);
    let bars: usize = opt(args, "--bars").and_then(|s| s.parse().ok()).unwrap_or(16);
    let comp = engine::compose(seed, bars);
    print_score(&comp.cf, &comp.cp);
    if let Some(out) = opt(args, "--out") {
        let bytes = engine::write_smf_named(&comp, Some(&format!("seed:{seed}")));
        std::fs::write(out, bytes).expect("write midi");
        println!("wrote {out}");
    }
    ExitCode::SUCCESS
}

fn cmd_embed(args: &[String]) -> ExitCode {
    // The nonce keys the keystream and travels in the framing; it must be
    // unique per (passphrase, message). Default: time+pid mix (uniqueness,
    // not secrecy — that is what the passphrase is for).
    let seed = opt(args, "--seed").map(parse_seed).unwrap_or_else(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        nanos ^ ((std::process::id() as u64) << 32)
    });
    let min_len: usize = opt(args, "--bars").and_then(|s| s.parse().ok()).unwrap_or(16);
    let message = opt(args, "--message").unwrap_or("");
    let key = opt(args, "--key").unwrap_or("");
    // M5: refuse obviously weak passphrases at embed time. Extraction keeps
    // accepting anything (the sender chose the key; guessing cost is the
    // attacker's problem). --allow-weak-key is for demos/tests only.
    if !has_flag(args, "--allow-weak-key") {
        if let Some(why) = passphrase_weakness(key) {
            eprintln!(
                "refusing weak passphrase ({why}); the 100k-round stretch slows offline\n\
                 guessing but entropy is the only real defense — use 12+ characters with\n\
                 6+ distinct characters (pass --allow-weak-key to override for demos)"
            );
            return ExitCode::from(2);
        }
    }
    let out = match opt(args, "--out") {
        Some(o) => o,
        None => {
            eprintln!("--out is required");
            return ExitCode::from(2);
        }
    };
    let species = match parse_species(args) {
        Some(s) => s,
        None => return ExitCode::from(2),
    };
    match stego::embed_species(message.as_bytes(), key, seed, min_len, species) {
        Ok((comp, len)) => {
            let (cf, cp) = match &comp {
                stego::Embedded::First(c) => (&c.cf, &c.cp),
                stego::Embedded::Second(c) => (&c.cf, &c.cp),
            };
            print_score(cf, cp);
            // No track name: embedded files carry no identifying metadata.
            let bytes = match &comp {
                stego::Embedded::First(c) => engine::write_smf_named(c, None),
                stego::Embedded::Second(c) => engine::write_smf2_named(c, None),
            };
            std::fs::write(out, bytes).expect("write midi");
            let species_name = match species {
                stego::Species::First => "species-1",
                stego::Species::Second => "species-2",
            };
            println!(
                "embedded {} bytes ({} bits payload + framing) into {} notes ({species_name}) -> {out} (nonce {})",
                message.len(),
                message.len() * 8,
                len,
                seed
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_extract(args: &[String]) -> ExitCode {
    let path = match opt(args, "--in") {
        Some(p) => p,
        None => {
            eprintln!("--in is required");
            return ExitCode::from(2);
        }
    };
    let key = opt(args, "--key").unwrap_or("");
    let bytes = std::fs::read(path).expect("read midi");
    let data = match engine::read_smf(&bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let (cf, cp) = match data.to_notes() {
        Some(v) => v,
        None => {
            eprintln!("MIDI data is not a countersteg cover (voice geometry or pitch set)");
            return ExitCode::FAILURE;
        }
    };
    // Species auto-detected from voice geometry; the nonce is read from the
    // bitstream; only the key is needed.
    match stego::extract(&cf, &cp, key) {
        Ok(msg) => {
            println!("{}", String::from_utf8_lossy(&msg));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_stats(args: &[String]) -> ExitCode {
    let path = match opt(args, "--in") {
        Some(p) => p,
        None => {
            eprintln!("--in is required");
            return ExitCode::from(2);
        }
    };
    let bytes = std::fs::read(path).expect("read midi");
    let data = engine::read_smf(&bytes).expect("parse midi");
    println!("cf notes: {}  cp notes: {}", data.cf.len(), data.cp.len());
    println!("cf entropy: {:.3} bits/byte", entropy::shannon_entropy(&data.cf));
    println!("cp entropy: {:.3} bits/byte", entropy::shannon_entropy(&data.cp));
    let len = data.cf.len();
    println!(
        "capacity estimate at {len} bars: species-1 ~{} bits, species-2 ~{} bits",
        stego::available_bits_species(0, len, stego::Species::First),
        stego::available_bits_species(0, len, stego::Species::Second),
    );
    match data.to_notes() {
        Some((cf, cp)) => match stego::replay_decisions(&cf, &cp) {
            Ok(ds) => {
                let species = if cp.len() == 2 * cf.len() { "species-2" } else { "species-1" };
                let cap = engine::capacity_bits(&ds);
                println!("{species}: decisions: {}  channel capacity: {cap} bits (~{} bytes)", ds.len(), cap / 8);
            }
            Err(e) => println!("decision replay: {e}"),
        },
        None => println!("voice geometry fits neither species"),
    }
    if let Some(name) = data.track_name {
        println!("track name: {name}");
    }
    ExitCode::SUCCESS
}
