//! BrainpoolP512r1 inner KEM: HKDF-BLAKE3 from ECDH shared secret (`spec/CESS-v0.2.md` Section 8.3).

use crate::hkdf_blake3::hkdf_blake3;

/// Verify HKDF rows in `ecdh_p512_inner.toml` (`case_kind = "hkdf_inner_key"`).
pub fn verify_ecdh_p512_inner_toml(toml_str: &str) -> Result<(), String> {
    let root: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("ecdh_p512_inner.toml parse: {e}"))?;
    let arr = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "ecdh_p512_inner.toml: missing vectors array".to_string())?;
    for (i, row) in arr.iter().enumerate() {
        let kind = row
            .get("case_kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing case_kind"))?;
        if kind != "hkdf_inner_key" {
            continue;
        }
        let ikm = hex::decode(
            row.get("hkdf_input_key_material_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing hkdf_input_key_material_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] ikm: {e}"))?;
        let salt_hex = row
            .get("hkdf_salt_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing hkdf_salt_hex"))?;
        let salt = hex::decode(salt_hex).map_err(|e| format!("vectors[{i}] salt: {e}"))?;
        let info = row
            .get("hkdf_info_utf8")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing hkdf_info_utf8"))?;
        let exp = hex::decode(
            row.get("expected_inner_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing expected_inner_key_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] expected_inner_key_hex: {e}"))?;
        let got = hkdf_blake3(&ikm, &salt, info.as_bytes(), exp.len());
        if got != exp {
            return Err(format!(
                "vectors[{i}]: HKDF-BLAKE3 inner key mismatch for {}",
                row.get("suite_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
            ));
        }
    }
    Ok(())
}
