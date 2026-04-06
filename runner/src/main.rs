//! CESS conformance runner: loads vector files, parses TOML, and verifies cryptographic KATs.
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

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
                     Exits 0 if all TOML vector files parse and cryptographic KATs verify."
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
        "blake3_integrity.toml",
        "classical_suite_id_matrix.toml",
        "twofish.toml",
        "ed25519_signing.toml",
        "ecdh_p512_inner.toml",
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
        "cess-runner: level={} vectors_dir={} parse PASS={} FAIL={}",
        level,
        dir.display(),
        ok,
        fail
    );

    if fail > 0 {
        std::process::exit(1);
    }

    let twofish = fs::read_to_string(dir.join("twofish.toml")).expect("twofish.toml");
    let hkdf = fs::read_to_string(dir.join("hkdf_blake3.toml")).expect("hkdf_blake3.toml");
    let blake3_int = fs::read_to_string(dir.join("blake3_integrity.toml")).expect("blake3_integrity.toml");
    let ed25519 = fs::read_to_string(dir.join("ed25519_signing.toml")).expect("ed25519_signing.toml");
    let ecdh_p512 = fs::read_to_string(dir.join("ecdh_p512_inner.toml")).expect("ecdh_p512_inner.toml");
    let matrix = fs::read_to_string(dir.join("classical_suite_id_matrix.toml")).expect("matrix");

    match cess_runner::verify_all_crypto_vectors(
        &twofish,
        &hkdf,
        &blake3_int,
        &ed25519,
        &ecdh_p512,
        &matrix,
    ) {
        Ok(()) => println!("PASS crypto KAT verification"),
        Err(e) => {
            eprintln!("FAIL crypto KAT verification: {e}");
            std::process::exit(1);
        }
    }

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/verify_p512_ecdh_kat.py");
    let status = Command::new("python3")
        .arg(&script)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("FAIL spawn python3 for P512 ECDH cross-check: {e}");
            std::process::exit(1);
        });
    if !status.success() {
        eprintln!("FAIL scripts/verify_p512_ecdh_kat.py (BrainpoolP512r1 ECDH)");
        std::process::exit(1);
    }
    println!("PASS P512 ECDH Python cross-check");

    println!(
        "cess-runner: level={} vectors_dir={} summary OK",
        level,
        dir.display()
    );
}
