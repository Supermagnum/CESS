//! Run C2SP Wycheproof ChaCha20-Poly1305 vectors against the Rust `chacha20poly1305` crate.
//! Input: JSON from https://github.com/C2SP/wycheproof (Apache-2.0 test data).
#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

const NONCE_LEN: usize = 12;

#[derive(Debug, Deserialize)]
struct WycheproofFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(default)]
    tests: Vec<WycheproofTest>,
}

#[derive(Debug, Deserialize)]
struct WycheproofTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(default)]
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("hex decode tcId: {}", e))
}

fn run_one(t: &WycheproofTest) -> Result<(), String> {
    let key = hex_decode(&t.key)?;
    let iv = hex_decode(&t.iv)?;
    let aad = hex_decode(&t.aad)?;
    let msg = hex_decode(&t.msg)?;
    let ct = hex_decode(&t.ct)?;
    let tag = hex_decode(&t.tag)?;

    if key.len() != 32 {
        return Err(format!("tcId {}: key length {}", t.tc_id, key.len()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| e.to_string())?;

    match t.result.as_str() {
        "valid" => {
            if iv.len() != NONCE_LEN {
                return Err(format!(
                    "tcId {}: valid vector but iv length {}",
                    t.tc_id,
                    iv.len()
                ));
            }
            let nonce = chacha20poly1305::Nonce::from_slice(&iv);
            let got = cipher
                .encrypt(nonce, Payload { msg: &msg, aad: &aad })
                .map_err(|e| format!("tcId {} encrypt: {}", t.tc_id, e))?;
            let mut want = ct;
            want.extend_from_slice(&tag);
            if got != want {
                return Err(format!(
                    "tcId {}: ciphertext+tag mismatch (got {} want {})",
                    t.tc_id,
                    got.len(),
                    want.len()
                ));
            }
            Ok(())
        }
        "invalid" => {
            if iv.len() != NONCE_LEN {
                // RFC 8439 IETF construction uses 12-byte nonces; wrong length is unusable.
                return Ok(());
            }
            let nonce = chacha20poly1305::Nonce::from_slice(&iv);
            let mut combined = ct;
            combined.extend_from_slice(&tag);
            match cipher.decrypt(nonce, Payload { msg: &combined, aad: &aad }) {
                Ok(_) => Err(format!(
                    "tcId {}: decrypt unexpectedly succeeded ({})",
                    t.tc_id, t.comment
                )),
                Err(_) => Ok(()),
            }
        }
        other => Err(format!("tcId {}: unknown result {:?}", t.tc_id, other)),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = if args.len() >= 2 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/wycheproof/chacha20_poly1305_test.json")
    };

    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wycheproof_chacha: cannot read {}: {}", path.display(), e);
            process::exit(2);
        }
    };

    let file: WycheproofFile = match serde_json::from_str(&raw) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("wycheproof_chacha: JSON parse: {}", e);
            process::exit(2);
        }
    };

    let mut total = 0u32;
    let mut fail = 0u32;
    for g in &file.test_groups {
        for t in &g.tests {
            total += 1;
            if let Err(e) = run_one(t) {
                eprintln!("FAIL tcId {}: {}", t.tc_id, e);
                fail += 1;
            }
        }
    }

    println!(
        "wycheproof_chacha: file={} total={} pass={} fail={}",
        path.display(),
        total,
        total - fail,
        fail
    );

    if fail > 0 {
        process::exit(1);
    }
}
