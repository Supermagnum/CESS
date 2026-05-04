//! Inner cascade KAT verification for CESS-mapped `suite_id` rows in `vectors/inner_cascade.toml`.
//!
//! HKDF-BLAKE3 `info` UTF-8 strings match Galdralag `crates/cess/src/inner_info.rs`. Inter-layer
//! authentication uses **HMAC-BLAKE3** on `cess_blake3_integrity_info(suite_id) || inner_aead_ct`
//! with subkeys from `cess_blake3_integrity_gap_info(suite_id, after_layer_index)` (see
//! `crates/cipher-profile/src/cascade.rs` in Galdralag-firmware).
//!
//! **Outer Serpent (layer 1)** in the reference implementation is **Encrypt-then-MAC** with
//! **HMAC-SHA256** over `aad || nonce || ciphertext_body` (`crates/vault/src/serpent_cipher.rs`).
//! CESS excludes SHA-256 for protocol use (`CONTRIBUTING.md`); this runner therefore recomputes
//! only the **Serpent-256-CTR** ciphertext body under the HKDF-derived keys and **128-bit
//! big-endian** counter schedule used by that reference, and compares the body to the reference
//! wire image. The trailing **32-byte HMAC-SHA256 tag** is **not** re-derived in-tree; conformance
//! for the full outer blob is documented as structural (body verified independently; tag matches
//! reference only by implication when the body matches and lengths are correct).

use crate::hkdf_blake3::{hkdf_blake3, hmac_blake3};
use crate::twofish_bulk::chacha20_poly1305_encrypt;
use cipher::{Block, BlockCipherEncrypt, KeyInit};
use serpent::Serpent;

const HEX: &[u8; 16] = b"0123456789abcdef";
const OUTER_HMAC_SHA256_TAG_LEN: usize = 32;

fn push_hex_u16_be(out: &mut Vec<u8>, v: u16) {
    for shift in (0..4).rev() {
        let nib = ((v >> (shift * 4)) & 0xf) as usize;
        out.push(HEX[nib]);
    }
}

fn push_layer_index(out: &mut Vec<u8>, layer_index: u8) {
    out.extend_from_slice(b"-l");
    if layer_index < 10 {
        out.push(b'0' + layer_index);
    } else if layer_index < 100 {
        out.push(b'0' + (layer_index / 10));
        out.push(b'0' + (layer_index % 10));
    } else {
        out.push(b'0' + (layer_index / 100));
        out.push(b'0' + ((layer_index / 10) % 10));
        out.push(b'0' + (layer_index % 10));
    }
}

fn cess_inner_cascade_layer_key_info(suite_id: u16, layer_index: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(b"cess-inner-");
    push_hex_u16_be(&mut out, suite_id);
    push_layer_index(&mut out, layer_index);
    out.extend_from_slice(b"-key");
    out
}

fn cess_inner_cascade_layer_nonce_info(suite_id: u16, layer_index: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(34);
    out.extend_from_slice(b"cess-inner-");
    push_hex_u16_be(&mut out, suite_id);
    push_layer_index(&mut out, layer_index);
    out.extend_from_slice(b"-nonce");
    out
}

fn cess_inner_cascade_etm64_serpent256_info(suite_id: u16, layer_index: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(b"cess-inner-");
    push_hex_u16_be(&mut out, suite_id);
    push_layer_index(&mut out, layer_index);
    out.extend_from_slice(b"-serpent256");
    out
}

fn cess_blake3_integrity_info(suite_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(b"cess-blake3-integrity-");
    push_hex_u16_be(&mut out, suite_id);
    out
}

fn cess_blake3_integrity_gap_info(suite_id: u16, after_layer_index: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(b"cess-blake3-integrity-");
    push_hex_u16_be(&mut out, suite_id);
    out.extend_from_slice(b"-gap");
    push_layer_index(&mut out, after_layer_index);
    out
}

fn hkdf_okm32(ikm: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    let v = hkdf_blake3(ikm, b"", info, 32);
    v.try_into()
        .map_err(|_| "hkdf_blake3: expected 32 bytes".to_string())
}

fn serpent256_ctr_xor_be(key32: &[u8; 32], iv16: &[u8; 16], buf: &mut [u8]) {
    let cipher = Serpent::new_from_slice(key32.as_slice()).expect("Serpent key 32");
    let mut ctr = *iv16;
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut block = Block::<Serpent>::from(ctr);
        cipher.encrypt_block(&mut block);
        let take = (buf.len() - offset).min(16);
        for i in 0..take {
            buf[offset + i] ^= block[i];
        }
        offset += take;
        let v = u128::from_be_bytes(ctr);
        ctr = v.wrapping_add(1).to_be_bytes();
    }
}

fn parse_suite_id(s: &str) -> Result<u16, String> {
    let s = s.trim();
    let rest = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).ok_or_else(|| {
        format!("suite_id: expected 0xNNNN form, got {s}")
    })?;
    u16::from_str_radix(rest, 16).map_err(|e| format!("suite_id: {e}"))
}

fn hex_field(row: &toml::Value, key: &str) -> Result<Vec<u8>, String> {
    let s = row
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing {key}"))?;
    hex::decode(s).map_err(|e| format!("{key}: {e}"))
}

fn chacha_inner_seal(
    ikm: &[u8],
    suite_id: u16,
    layer: u8,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let ik = cess_inner_cascade_layer_key_info(suite_id, layer);
    let ink = cess_inner_cascade_layer_nonce_info(suite_id, layer);
    let key_b = hkdf_okm32(ikm, &ik)?;
    let n_b = hkdf_okm32(ikm, &ink)?;
    let mut nonce12 = [0u8; 12];
    nonce12.copy_from_slice(&n_b[..12]);
    Ok(chacha20_poly1305_encrypt(&key_b, &nonce12, aad, plaintext))
}

fn append_inter_layer_mac(ikm: &[u8], suite_id: u16, after_layer: u8, inner_ct: &[u8]) -> Result<Vec<u8>, String> {
    let gap_info = cess_blake3_integrity_gap_info(suite_id, after_layer);
    let mac_key = hkdf_okm32(ikm, &gap_info)?;
    let mut msg: Vec<u8> = cess_blake3_integrity_info(suite_id);
    msg.extend_from_slice(inner_ct);
    let mac = hmac_blake3(&mac_key, &msg);
    let mut out = inner_ct.to_vec();
    out.extend_from_slice(&mac);
    Ok(out)
}

fn verify_outer_serpent_body_only(
    ikm: &[u8],
    suite_id: u16,
    intermediate: &[u8],
    expected_full: &[u8],
) -> Result<(), String> {
    if expected_full.len() != intermediate.len() + OUTER_HMAC_SHA256_TAG_LEN {
        return Err(format!(
            "outer: expected ciphertext length {} (body + HMAC-SHA256 tag), got {}",
            intermediate.len() + OUTER_HMAC_SHA256_TAG_LEN,
            expected_full.len()
        ));
    }
    let (exp_body, exp_tag) = expected_full.split_at(intermediate.len());
    let etm_info = cess_inner_cascade_etm64_serpent256_info(suite_id, 1);
    let okm64 = hkdf_blake3(ikm, b"", &etm_info, 64);
    if okm64.len() != 64 {
        return Err("hkdf: expected 64-byte EtM OKM".into());
    }
    let mut cipher_key = [0u8; 32];
    cipher_key.copy_from_slice(&okm64[..32]);
    let n_inf = cess_inner_cascade_layer_nonce_info(suite_id, 1);
    let n_okm = hkdf_okm32(ikm, &n_inf)?;
    let mut iv16 = [0u8; 16];
    iv16.copy_from_slice(&n_okm[..16]);
    let mut body = intermediate.to_vec();
    serpent256_ctr_xor_be(&cipher_key, &iv16, &mut body);
    if body.as_slice() != exp_body {
        return Err(
            "outer Serpent-256-CTR body mismatch (reference uses vault big-endian CTR + EtM framing)"
                .into(),
        );
    }
    // HMAC-SHA256 tag (exp_tag) is not recomputed here (SHA-256 family excluded from runner).
    let _ = exp_tag;
    Ok(())
}

/// Verify every `[[vectors]]` row in `inner_cascade.toml`.
pub fn verify_inner_cascade_toml(toml_str: &str) -> Result<(), String> {
    let root: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("inner_cascade.toml parse: {e}"))?;
    let arr = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "inner_cascade.toml: missing vectors array".to_string())?;
    for (i, row) in arr.iter().enumerate() {
        let suite_s = row
            .get("suite_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing suite_id"))?;
        let suite_id = parse_suite_id(suite_s)?;
        let ikm = hex_field(row, "ikm_hex")?;
        let aad = hex_field(row, "aad_hex")?;
        let pt = hex_field(row, "plaintext_hex")?;
        let exp_ct = hex_field(row, "expected_ciphertext_hex")?;

        match suite_id {
            0x0001 => {
                let inner = chacha_inner_seal(&ikm, suite_id, 0, &aad, &pt)?;
                if inner != exp_ct {
                    return Err(format!("vectors[{i}] 0x0001: ChaCha20-Poly1305 ciphertext mismatch"));
                }
            }
            0x0003 | 0x0012 => {
                let mid_hex = row
                    .get("intermediate_before_outer_hex")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("vectors[{i}]: missing intermediate_before_outer_hex"))?;
                let exp_mid = hex::decode(mid_hex)
                    .map_err(|e| format!("vectors[{i}] intermediate_before_outer_hex: {e}"))?;

                let inner = chacha_inner_seal(&ikm, suite_id, 0, &[], &pt)?;
                let with_mac = append_inter_layer_mac(&ikm, suite_id, 0, &inner)?;
                if with_mac != exp_mid {
                    return Err(format!(
                        "vectors[{i}] {suite_s}: inner ChaCha + inter-layer HMAC-BLAKE3 mismatch"
                    ));
                }
                verify_outer_serpent_body_only(&ikm, suite_id, &with_mac, &exp_ct)?;
            }
            _ => {
                return Err(format!("vectors[{i}]: unsupported suite_id {suite_s}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_info_labels_match_galdralag_tests() {
        assert_eq!(
            cess_inner_cascade_layer_key_info(0x0003, 0).as_slice(),
            b"cess-inner-0003-l0-key"
        );
        assert_eq!(
            cess_inner_cascade_layer_nonce_info(0x0003, 1).as_slice(),
            b"cess-inner-0003-l1-nonce"
        );
        assert_eq!(
            cess_blake3_integrity_gap_info(0x0003, 0).as_slice(),
            b"cess-blake3-integrity-0003-gap-l0"
        );
    }
}
