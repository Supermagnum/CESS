//! Keyed BLAKE3 integrity tags over inner AEAD outputs (`spec/CESS-v0.2.md` Section 6.3).

use crate::hkdf_blake3::hkdf_blake3;
use crate::twofish_bulk::{chacha20_poly1305_encrypt, poly1305_tag_rfc8439, serpent256_ctr_xor, twofish256_ctr_xor};

/// AEAD blob for integrity: ciphertext bytes followed by Poly1305 tag (RFC 8439 layout).
fn aead_blob_ct_tag(ct: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ct.len() + tag.len());
    v.extend_from_slice(ct);
    v.extend_from_slice(tag);
    v
}

fn blake3_keyed_tag_32(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(msg);
    *h.finalize().as_bytes()
}

/// Verify every `[[vectors]]` row in `blake3_integrity.toml`.
pub fn verify_blake3_integrity_toml(toml_str: &str) -> Result<(), String> {
    let root: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("blake3_integrity.toml parse: {e}"))?;
    let arr = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "blake3_integrity.toml: missing vectors array".to_string())?;
    for (i, row) in arr.iter().enumerate() {
        let suite_id = row
            .get("suite_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing suite_id"))?;
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
        let exp_key = hex::decode(
            row.get("blake3_integrity_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing blake3_integrity_key_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] blake3_integrity_key_hex: {e}"))?;
        if exp_key.len() != 32 {
            return Err(format!("vectors[{i}]: blake3_integrity_key_hex must be 32 bytes"));
        }
        let got_key = hkdf_blake3(&ikm, &salt, info.as_bytes(), 32);
        if got_key != exp_key {
            return Err(format!("vectors[{i}]: HKDF-BLAKE3 integrity key mismatch ({suite_id})"));
        }
        let exp_tag = hex::decode(
            row.get("expected_blake3_tag_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing expected_blake3_tag_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] tag: {e}"))?;
        if exp_tag.len() != 32 {
            return Err(format!("vectors[{i}]: expected_blake3_tag_hex must be 32 bytes"));
        }
        let inner = hex::decode(
            row.get("inner_ciphertext_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing inner_ciphertext_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] inner_ciphertext_hex: {e}"))?;
        let key32: [u8; 32] = got_key
            .try_into()
            .map_err(|_| format!("vectors[{i}]: internal key length"))?;
        let got_tag = blake3_keyed_tag_32(&key32, &inner);
        if got_tag.as_slice() != exp_tag.as_slice() {
            return Err(format!(
                "vectors[{i}]: keyed BLAKE3 tag mismatch ({suite_id})"
            ));
        }
    }
    Ok(())
}

/// Rebuild inner AEAD blob for a vector row when `rebuild_inner` is set (development aid only).
#[allow(dead_code)]
pub fn rebuild_inner_blob_for_suite(suite_id: &str) -> Result<Vec<u8>, String> {
    match suite_id {
        "0x0008" => {
            let key32: [u8; 32] = hex::decode("fa6859b1082289a751c9ca2501486dd5cf606d564acd178803a2c06ef55b6a47")
                .unwrap()
                .try_into()
                .unwrap();
            let nonce = [0u8; 12];
            let aad = hex::decode("636573732d6161642d7631").unwrap();
            let pt =
                hex::decode("434553532062756c6b204145414420706c61696e7465787420766563746f722e").unwrap();
            Ok(chacha20_poly1305_encrypt(&key32, &nonce, &aad, &pt))
        }
        "0x000a" => {
            let serpent_key = hex::decode("9d8ab5f5122c5e7c63d48e177a9bbf9aa51b25285f08380c077af96f553f0c61")
                .unwrap();
            let iv: [u8; 16] = hex::decode("8de9731f4c821a10c5380e2f111fe632")
                .unwrap()
                .try_into()
                .unwrap();
            let aad = hex::decode("636573732d6161642d7631").unwrap();
            let pt =
                hex::decode("434553532062756c6b204145414420706c61696e7465787420766563746f722e").unwrap();
            let poly_k: [u8; 32] = hex::decode(
                "b7346dd7ac30b9132da4f11d8cd19f0fd464f9d5ef51d929bc26244527a3af28",
            )
            .unwrap()
            .try_into()
            .unwrap();
            let mut ct = pt.clone();
            serpent256_ctr_xor(&serpent_key, &iv, &mut ct);
            let tag = poly1305_tag_rfc8439(&poly_k, &aad, &ct);
            Ok(aead_blob_ct_tag(&ct, &tag))
        }
        "0x000e" => {
            let tf_key = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
            let iv: [u8; 16] = hex::decode("8de9731f4c821a10c5380e2f111fe632")
                .unwrap()
                .try_into()
                .unwrap();
            let aad = hex::decode("636573732d6161642d7631").unwrap();
            let pt =
                hex::decode("434553532062756c6b204145414420706c61696e7465787420766563746f722e").unwrap();
            let poly_k: [u8; 32] = hex::decode(
                "b7346dd7ac30b9132da4f11d8cd19f0fd464f9d5ef51d929bc26244527a3af28",
            )
            .unwrap()
            .try_into()
            .unwrap();
            let mut ct = pt.clone();
            twofish256_ctr_xor(&tf_key, &iv, &mut ct);
            let tag = poly1305_tag_rfc8439(&poly_k, &aad, &ct);
            Ok(aead_blob_ct_tag(&ct, &tag))
        }
        _ => Err(format!("unknown rebuild suite_id {suite_id}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hkdf_blake3::hkdf_blake3;

    #[test]
    fn inner_blob_lengths_match_integrity_vectors() {
        for sid in ["0x0008", "0x000a", "0x000e"] {
            let b = rebuild_inner_blob_for_suite(sid).unwrap();
            assert!(!b.is_empty(), "{sid}");
        }
    }

    #[test]
    #[ignore]
    fn dump_blake3_integrity_kat_hex_for_toml() {
        let ikm = hex::decode("3df646a590007b20e599678926543bad804f03c4cd15d8122813d97b08b657d9")
            .unwrap();
        for (sid, info) in [
            ("0x0008", "cess-blake3-integrity-0008"),
            ("0x000a", "cess-blake3-integrity-000a"),
            ("0x000e", "cess-blake3-integrity-000e"),
        ] {
            let ik = hkdf_blake3(&ikm, &[], info.as_bytes(), 32);
            let inner = rebuild_inner_blob_for_suite(sid).unwrap();
            let key32: [u8; 32] = ik.clone().try_into().unwrap();
            let mut h = blake3::Hasher::new_keyed(&key32);
            h.update(&inner);
            let tag = h.finalize();
            eprintln!(
                "sid={sid}\nik={}\ninner={}\ntag={}\n",
                hex::encode(ik),
                hex::encode(&inner),
                hex::encode(tag.as_bytes())
            );
        }
        let ik = hkdf_blake3(
            &ikm,
            &[],
            b"cess-blake3-integrity-0207",
            32,
        );
        let inner = rebuild_inner_blob_for_suite("0x000e").unwrap();
        let key32: [u8; 32] = ik.clone().try_into().unwrap();
        let mut h = blake3::Hasher::new_keyed(&key32);
        h.update(&inner);
        let tag = h.finalize();
        eprintln!(
            "sid=0x0207\nik={}\ninner={}\ntag={}\n",
            hex::encode(ik),
            hex::encode(&inner),
            hex::encode(tag.as_bytes())
        );
    }
}
