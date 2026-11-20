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
    let seed = opt(args, "--seed").map(parse_seed).unwrap_or(0);
    let min_len: usize = opt(args, "--bars").and_then(|s| s.parse().ok()).unwrap_or(16);
    let message = opt(args, "--message").unwrap_or("");
    let key = opt(args, "--key").unwrap_or("");
    let out = match opt(args, "--out") {
        Some(o) => o,
        None => {
            eprintln!("--out is required");
            return ExitCode::from(2);
        }
    };
    match stego::embed(message.as_bytes(), key, seed, min_len) {
        Ok((comp, len)) => {
            print_score(&comp.cf, &comp.cp);
            let bytes = engine::write_smf_named(&comp, Some(&format!("seed:{seed}")));
            std::fs::write(out, bytes).expect("write midi");
            println!(
                "embedded {} bytes ({} bits payload + framing) into {} notes -> {out}",
                message.len(),
                message.len() * 8,
                len
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
    let seed = data
        .track_name
        .as_deref()
        .and_then(|n| n.strip_prefix("seed:"))
        .and_then(|s| s.parse::<u64>().ok());
    let seed = match seed {
        Some(s) => s,
        None => {
            eprintln!("no seed found in MIDI track name");
            return ExitCode::FAILURE;
        }
    };
    let cf: Vec<engine::Note> = data.cf.iter().map(|&m| engine::Note::from_midi(m).unwrap()).collect();
    let cp: Vec<engine::Note> = data.cp.iter().map(|&m| engine::Note::from_midi(m).unwrap()).collect();
    match stego::extract(&cf, &cp, key, seed) {
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
    let cf: Vec<engine::Note> = data.cf.iter().map(|&m| engine::Note::from_midi(m).unwrap()).collect();
    let cp: Vec<engine::Note> = data.cp.iter().map(|&m| engine::Note::from_midi(m).unwrap()).collect();
    match engine::decisions_of(&cf, &cp) {
        Ok(ds) => {
            let cap = engine::capacity_bits(&ds);
            println!("decisions: {}  channel capacity: {cap} bits (~{} bytes)", ds.len(), cap / 8);
        }
        Err(e) => println!("decision replay: {e}"),
    }
    if let Some(name) = data.track_name {
        println!("track name: {name}");
    }
    ExitCode::SUCCESS
}
