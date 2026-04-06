//! CESS conformance runner: loads vector files and reports parse status.
//! Full primitive verification is implemented incrementally against `vectors/*.toml`.
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let mut args = env::args().skip(1);
    let mut level = String::from("core");
    let mut vectors_dir: Option<PathBuf> = None;
    let mut impl_path: Option<PathBuf> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--level" => level = args.next().unwrap_or_else(|| "core".into()),
            "--vectors" => vectors_dir = args.next().map(PathBuf::from),
            "--impl" => impl_path = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                eprintln!(
                    "Usage: cess-runner [--level core|full|pq] [--vectors DIR] [--impl PATH]\n\
                     Exits 0 if all TOML vector files parse; prints summary."
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let dir = vectors_dir.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors")
    });

    if let Some(p) = &impl_path {
        if !p.exists() {
            eprintln!("SKIP: --impl path does not exist: {}", p.display());
        }
    }

    let mut ok = 0usize;
    let mut fail = 0usize;
    for name in [
        "sss.toml",
        "blake3.toml",
        "argon2id.toml",
        "hkdf_blake3.toml",
        "ecdh_brainpool.toml",
        "bulk_aead.toml",
        "twofish.toml",
        "pin_wrap.toml",
        "reed_solomon.toml",
        "rejection.toml",
        "integration.toml",
        "wycheproof_chacha.toml",
        "rfc6932_brainpool.toml",
        "rfc7027_brainpool.toml",
        "rfc5639_brainpool.toml",
    ] {
        let path = dir.join(name);
        match fs::read_to_string(&path) {
            Err(e) => {
                eprintln!("FAIL read {}: {}", path.display(), e);
                fail += 1;
            }
            Ok(s) => match s.parse::<toml::Value>() {
                Err(e) => {
                    eprintln!("FAIL parse {}: {}", path.display(), e);
                    fail += 1;
                }
                Ok(_) => {
                    println!("PASS parse {}", name);
                    ok += 1;
                }
            },
        }
    }

    println!(
        "cess-runner: level={} vectors_dir={} summary PASS={} FAIL={}",
        level,
        dir.display(),
        ok,
        fail
    );

    if fail > 0 {
        std::process::exit(1);
    }
}
