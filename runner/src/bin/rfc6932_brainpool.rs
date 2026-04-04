//! Brainpool ECDH JSON (same schema as RFC 6932 / RFC 7027 corpora): P-256 and P-384 only.
//! Compares `SharedSecret::raw_secret_bytes()` (x-coordinate) to `x_Z`.
//! Other curves: `scripts/rfc6932_brainpool.py`, `scripts/rfc7027_brainpool.py`, `scripts/brainpool_ecdh_common.py`.
#![forbid(unsafe_code)]

use bp256::BrainpoolP256r1;
use bp384::BrainpoolP384r1;
use elliptic_curve::{PublicKey, SecretKey};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Debug, Deserialize)]
struct FileRoot {
    curves: Vec<CurveRow>,
}

#[derive(Debug, Deserialize)]
struct CurveRow {
    id: String,
    #[serde(rename = "dA")]
    d_a: String,
    #[serde(rename = "x_qB")]
    x_qb: String,
    #[serde(rename = "y_qB")]
    y_qb: String,
    #[serde(rename = "x_Z")]
    x_z: String,
}

fn hex_decode(label: &str, s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("{label}: hex decode: {e}"))
}

fn check_p256(c: &CurveRow) -> Result<(), String> {
    let d_a = hex_decode("dA", &c.d_a)?;
    let x = hex_decode("x_qB", &c.x_qb)?;
    let y = hex_decode("y_qB", &c.y_qb)?;
    let expect = hex_decode("x_Z", &c.x_z)?;

    let sk = SecretKey::<BrainpoolP256r1>::from_slice(&d_a).map_err(|_| {
        format!("{}: invalid secret key scalar", c.id)
    })?;

    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    let pk = PublicKey::<BrainpoolP256r1>::from_sec1_bytes(&sec1)
        .map_err(|_| format!("{}: invalid peer public SEC1 point", c.id))?;

    let shared = sk.diffie_hellman(&pk);
    let got = shared.raw_secret_bytes().as_slice();
    if got != expect.as_slice() {
        return Err(format!(
            "{}: shared secret x-coordinate mismatch (got {} bytes, want {})",
            c.id,
            got.len(),
            expect.len()
        ));
    }
    Ok(())
}

fn check_p384(c: &CurveRow) -> Result<(), String> {
    let d_a = hex_decode("dA", &c.d_a)?;
    let x = hex_decode("x_qB", &c.x_qb)?;
    let y = hex_decode("y_qB", &c.y_qb)?;
    let expect = hex_decode("x_Z", &c.x_z)?;

    let sk = SecretKey::<BrainpoolP384r1>::from_slice(&d_a).map_err(|_| {
        format!("{}: invalid secret key scalar", c.id)
    })?;

    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    let pk = PublicKey::<BrainpoolP384r1>::from_sec1_bytes(&sec1)
        .map_err(|_| format!("{}: invalid peer public SEC1 point", c.id))?;

    let shared = sk.diffie_hellman(&pk);
    let got = shared.raw_secret_bytes().as_slice();
    if got != expect.as_slice() {
        return Err(format!(
            "{}: shared secret x-coordinate mismatch (got {} bytes, want {})",
            c.id,
            got.len(),
            expect.len()
        ));
    }
    Ok(())
}

fn main() {
    let path: PathBuf = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../testdata/rfc6932/rfc6932_brainpool_ecdh.json")
        });

    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("brainpool_ecdh_json: read {}: {e}", path.display());
        process::exit(1);
    });

    let root: FileRoot = serde_json::from_str(&raw).unwrap_or_else(|e| {
        eprintln!("brainpool_ecdh_json: JSON parse: {e}");
        process::exit(1);
    });

    let mut ran = 0u32;
    let mut errs: Vec<String> = Vec::new();

    for c in &root.curves {
        let r = match c.id.as_str() {
            "brainpoolP256r1" => {
                ran += 1;
                check_p256(c)
            }
            "brainpoolP384r1" => {
                ran += 1;
                check_p384(c)
            }
            _ => Ok(()),
        };
        if let Err(e) = r {
            errs.push(e);
        }
    }

    if errs.is_empty() {
        println!(
            "brainpool_ecdh_json: OK (RustCrypto bp256/bp384), curves checked: {ran}, file={}",
            path.display()
        );
    } else {
        for e in &errs {
            eprintln!("brainpool_ecdh_json: FAIL: {e}");
        }
        process::exit(1);
    }
}
