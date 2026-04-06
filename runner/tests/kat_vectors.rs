//! Integration: load vector files and run the same verification as `cess-runner` crypto phase.

use std::fs;
use std::path::PathBuf;

#[test]
fn verify_all_crypto_vectors_matches_main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    let twofish = fs::read_to_string(dir.join("twofish.toml")).expect("twofish.toml");
    let hkdf = fs::read_to_string(dir.join("hkdf_blake3.toml")).expect("hkdf_blake3.toml");
    let blake3_int = fs::read_to_string(dir.join("blake3_integrity.toml")).expect("blake3_integrity.toml");
    let ed25519 = fs::read_to_string(dir.join("ed25519_signing.toml")).expect("ed25519_signing.toml");
    let ecdh_p512 = fs::read_to_string(dir.join("ecdh_p512_inner.toml")).expect("ecdh_p512_inner.toml");
    let matrix = fs::read_to_string(dir.join("classical_suite_id_matrix.toml")).expect("matrix");
    cess_runner::verify_all_crypto_vectors(
        &twofish,
        &hkdf,
        &blake3_int,
        &ed25519,
        &ecdh_p512,
        &matrix,
    )
    .expect("verify_all_crypto_vectors");
}
