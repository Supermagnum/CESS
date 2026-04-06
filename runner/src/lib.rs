//! CESS conformance crypto verification (Twofish-CTR + Poly1305, cascades).
#![forbid(unsafe_code)]

pub mod blake3_integrity;
pub mod ecdh_p512_inner;
pub mod ed25519_signing;
pub mod hkdf_blake3;
pub mod twofish_bulk;
pub mod vector_manifest;

/// Run all cryptographic vector verifications required for CI (after TOML parse).
pub fn verify_all_crypto_vectors(
    twofish: &str,
    hkdf: &str,
    blake3_int: &str,
    ed25519: &str,
    ecdh_p512: &str,
    matrix: &str,
) -> Result<(), String> {
    hkdf_blake3::verify_hkdf_blake3_toml(hkdf)?;
    blake3_integrity::verify_blake3_integrity_toml(blake3_int)?;
    ed25519_signing::verify_ed25519_signing_toml(ed25519)?;
    ecdh_p512_inner::verify_ecdh_p512_inner_toml(ecdh_p512)?;
    twofish_bulk::verify_twofish_toml(twofish)?;
    vector_manifest::verify_classical_suite_matrix_toml(matrix)?;
    Ok(())
}
