//! HKDF-BLAKE3 (RFC 5869 structure, HMAC-BLAKE3 PRF) matching `scripts/generate_vectors.py`.

const HMAC_BLOCK: usize = 64;

fn hmac_blake3(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key = key.to_vec();
    if key.len() > HMAC_BLOCK {
        key = blake3::hash(&key).as_bytes().to_vec();
    }
    key.resize(HMAC_BLOCK, 0);
    let mut ipad = [0u8; HMAC_BLOCK];
    let mut opad = [0u8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5c;
    }
    let mut inner_input = Vec::with_capacity(HMAC_BLOCK + data.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(data);
    let inner = blake3::hash(&inner_input);
    let mut outer_input = Vec::with_capacity(HMAC_BLOCK + 32);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(inner.as_bytes());
    *blake3::hash(&outer_input).as_bytes()
}

/// HKDF-Expand with BLAKE3; empty `salt` uses 32 zero bytes (same as Python `hkdf_blake3`).
pub fn hkdf_blake3(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let salt_key: Vec<u8> = if salt.is_empty() {
        vec![0u8; 32]
    } else {
        salt.to_vec()
    };
    let prk = hmac_blake3(&salt_key, ikm);
    let mut okm = Vec::new();
    let mut t = Vec::new();
    let mut counter = 1u8;
    while okm.len() < length {
        let mut block_input = Vec::with_capacity(t.len() + info.len() + 1);
        block_input.extend_from_slice(&t);
        block_input.extend_from_slice(info);
        block_input.push(counter);
        t = hmac_blake3(&prk, &block_input).to_vec();
        okm.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(length);
    okm
}

/// Verify every `[[vectors]]` row in `hkdf_blake3.toml` (full file).
pub fn verify_hkdf_blake3_toml(toml_str: &str) -> Result<(), String> {
    let root: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("hkdf_blake3.toml parse: {e}"))?;
    let arr = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "hkdf_blake3.toml: missing vectors array".to_string())?;
    for (i, row) in arr.iter().enumerate() {
        let ikm = hex::decode(
            row
                .get("ikm_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing ikm_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] ikm_hex: {e}"))?;
        let salt_hex = row
            .get("salt_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing salt_hex"))?;
        let salt = hex::decode(salt_hex).map_err(|e| format!("vectors[{i}] salt_hex: {e}"))?;
        let info_utf8 = row
            .get("info_utf8")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing info_utf8"))?;
        let out_len = row
            .get("output_length")
            .and_then(|v| v.as_integer())
            .ok_or_else(|| format!("vectors[{i}]: missing output_length"))? as usize;
        let exp_hex = row
            .get("okm_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing okm_hex"))?;
        let exp = hex::decode(exp_hex).map_err(|e| format!("vectors[{i}] okm_hex: {e}"))?;
        let got = hkdf_blake3(&ikm, &salt, info_utf8.as_bytes(), out_len);
        if got != exp {
            return Err(format!("vectors[{i}]: HKDF-BLAKE3 okm mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn hkdf_blake3_toml_file_verifies() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/hkdf_blake3.toml");
        let s = fs::read_to_string(&path).expect("read hkdf_blake3.toml");
        verify_hkdf_blake3_toml(&s).expect("verify_hkdf_blake3_toml");
    }

    #[test]
    fn hkdf_matches_first_hkdf_blake3_vector() {
        let ikm = hex::decode("3df646a590007b20e599678926543bad804f03c4cd15d8122813d97b08b657d9")
            .unwrap();
        let okm = hkdf_blake3(&ikm, &[], b"cess-kem-v1", 32);
        assert_eq!(
            hex::encode(okm),
            "56c614e8527a62ffdf5dcd7e6f11514201a89016f125925019d81f81a9f5225c"
        );
    }

    #[test]
    fn hkdf_cess_inner_0013_from_p512_shared_secret() {
        let ss = hex::decode(
            "0cf4de5a030128978d3c47d470d1ba1b9bdc5a58962fc33cbd73b42ef33abb3a6ea4e01038e223cf2af6f729862550081ce1322bcba6bc7e5c0d4f2ff0f33d98",
        )
        .unwrap();
        let okm = hkdf_blake3(&ss, &[], b"cess-inner-0013", 32);
        assert_eq!(
            hex::encode(okm),
            "66cef42e828b14256fbc523156b7b2ff1c8f4ea7319f4fc63800557fa6ea04bd"
        );
    }
}
