//! Twofish-256-CTR + Poly1305 (RFC 8439 MAC layout) and CESS cascades.
//! Poly1305 matches ChaCha20-Poly1305 AEAD / Serpent profile: padded AAD, padded ciphertext, length block.

use chacha20poly1305::aead::{Aead, KeyInit as ChaChaKeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce};
use cipher::{BlockCipherEncrypt, KeyInit};
use generic_array::GenericArray;
use poly1305::Poly1305;
use serpent::Serpent;
use twofish::cipher::{Block as TfBlock, BlockEncrypt as _};
use twofish::Twofish;
use typenum::consts::U16;
use universal_hash::UniversalHash;

/// RFC 8439-style Poly1305 over `aad` and `ciphertext` (same construction as ChaCha20-Poly1305 AEAD).
pub fn poly1305_tag_rfc8439(poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(poly1305::Key::from_slice(poly_key));
    mac.update_padded(aad);
    mac.update_padded(ciphertext);
    let ad_len = aad.len() as u64;
    let ct_len = ciphertext.len() as u64;
    let mut lb = GenericArray::<u8, U16>::default();
    lb[..8].copy_from_slice(&ad_len.to_le_bytes());
    lb[8..].copy_from_slice(&ct_len.to_le_bytes());
    mac.update(core::slice::from_ref(&lb));
    mac.finalize().into()
}

/// Twofish-256-CTR: encrypt or decrypt `buf` in place (CTR XOR).
pub fn twofish256_ctr_xor(key32: &[u8], iv16: &[u8; 16], buf: &mut [u8]) {
    let cipher = Twofish::new_from_slice(key32).expect("Twofish key 16/24/32");
    let mut ctr = *iv16;
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut block = TfBlock::<Twofish>::from(ctr);
        cipher.encrypt_block(&mut block);
        let take = (buf.len() - offset).min(16);
        for i in 0..take {
            buf[offset + i] ^= block[i];
        }
        offset += take;
        for i in (0..16).rev() {
            ctr[i] = ctr[i].wrapping_add(1);
            if ctr[i] != 0 {
                break;
            }
        }
    }
}

/// Serpent-256-CTR in place (same CTR increment as `scripts/serpent_helper`).
pub fn serpent256_ctr_xor(key: &[u8], iv16: &[u8; 16], buf: &mut [u8]) {
    let cipher = Serpent::new_from_slice(key).expect("Serpent key length");
    let mut ctr = *iv16;
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut block = cipher::Block::<Serpent>::from(ctr);
        cipher.encrypt_block(&mut block);
        let take = (buf.len() - offset).min(16);
        for i in 0..take {
            buf[offset + i] ^= block[i];
        }
        offset += take;
        for i in (0..16).rev() {
            ctr[i] = ctr[i].wrapping_add(1);
            if ctr[i] != 0 {
                break;
            }
        }
    }
}

/// ChaCha20-Poly1305 seal: returns ciphertext || tag.
pub fn chacha20_poly1305_encrypt(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let c = ChaCha20Poly1305::new(ChaChaKey::from_slice(key32));
    let nonce = Nonce::from_slice(nonce12);
    c.encrypt(
        nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    )
    .expect("chacha encrypt")
}

/// Verify every `[[vectors]]` row in `vectors/twofish.toml` against this crate's Twofish/Poly1305/cascade implementation.
pub fn verify_twofish_toml(toml_str: &str) -> Result<(), String> {
    let root: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("twofish.toml parse: {e}"))?;
    let arr = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "twofish.toml: missing vectors array".to_string())?;
    for (i, row) in arr.iter().enumerate() {
        let suite_id = row
            .get("suite_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing suite_id"))?;
        match suite_id {
            "0x0004" | "0x0203" | "0x0207" => verify_single_row(row, suite_id)?,
            "0x0005" | "0x0204" => verify_chacha_twofish_row(row, suite_id)?,
            "0x0006" | "0x0205" => verify_twofish_serpent_row(row, suite_id)?,
            "0x0007" | "0x0206" => verify_triple_row(row, suite_id)?,
            _ => {
                return Err(format!("vectors[{i}]: unknown suite_id {suite_id}"));
            }
        }
    }
    Ok(())
}

fn hex_field(row: &toml::Value, key: &str) -> Result<Vec<u8>, String> {
    let s = row
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing {key}"))?;
    hex::decode(s).map_err(|e| format!("{key}: {e}"))
}

fn hex32(row: &toml::Value, key: &str) -> Result<[u8; 32], String> {
    let v = hex_field(row, key)?;
    v.try_into()
        .map_err(|_| format!("{key}: expected 32 bytes"))
}

fn verify_single_row(row: &toml::Value, suite_id: &str) -> Result<(), String> {
    let key = hex_field(row, "twofish_key_hex")?;
    let iv: [u8; 16] = hex_field(row, "ctr_iv_hex")?
        .try_into()
        .map_err(|_| "ctr_iv_hex: expected 16 bytes".to_string())?;
    let aad = hex_field(row, "aad_hex")?;
    let pt = hex_field(row, "plaintext_hex")?;
    let exp_ct = hex_field(row, "ciphertext_hex")?;
    let poly_k = hex32(row, "poly1305_key_hex")?;
    let exp_tag = hex_field(row, "tag_hex")?;
    if exp_tag.len() != 16 {
        return Err("tag_hex: expected 16 bytes".into());
    }
    if suite_id == "0x0207" {
        let _ik = hex32(row, "blake3_integrity_key_hex")?;
    }
    let mut ct = pt.clone();
    twofish256_ctr_xor(&key, &iv, &mut ct);
    if ct != exp_ct {
        return Err(format!("{suite_id}: ciphertext mismatch"));
    }
    let tag = poly1305_tag_rfc8439(&poly_k, &aad, &ct);
    if tag.as_slice() != exp_tag.as_slice() {
        return Err(format!("{suite_id}: Poly1305 tag mismatch"));
    }
    Ok(())
}

fn verify_chacha_twofish_row(row: &toml::Value, suite_id: &str) -> Result<(), String> {
    let chacha_key = hex32(row, "chacha_key_hex")?;
    let nonce: [u8; 12] = hex_field(row, "chacha_nonce_hex")?
        .try_into()
        .map_err(|_| "chacha_nonce_hex: expected 12 bytes".to_string())?;
    let tf_key = hex_field(row, "twofish_key_hex")?;
    let iv: [u8; 16] = hex_field(row, "ctr_iv_hex")?
        .try_into()
        .map_err(|_| "ctr_iv_hex: expected 16 bytes".to_string())?;
    let aad = hex_field(row, "aad_hex")?;
    let pt = hex_field(row, "plaintext_hex")?;
    let exp_inner = hex_field(row, "inner_ciphertext_hex")?;
    let exp_outer = hex_field(row, "outer_ciphertext_hex")?;
    let poly_k = hex32(row, "poly1305_key_hex")?;
    let exp_tag = hex_field(row, "outer_tag_hex")?;
    if exp_tag.len() != 16 {
        return Err("outer_tag_hex: expected 16 bytes".into());
    }
    let inner = chacha20_poly1305_encrypt(&chacha_key, &nonce, &aad, &pt);
    if inner != exp_inner {
        return Err(format!("{suite_id}: inner ciphertext mismatch"));
    }
    let mut outer = inner.clone();
    twofish256_ctr_xor(&tf_key, &iv, &mut outer);
    if outer != exp_outer {
        return Err(format!("{suite_id}: outer ciphertext mismatch"));
    }
    let tag = poly1305_tag_rfc8439(&poly_k, &aad, &outer);
    if tag.as_slice() != exp_tag.as_slice() {
        return Err(format!("{suite_id}: outer Poly1305 tag mismatch"));
    }
    Ok(())
}

fn verify_twofish_serpent_row(row: &toml::Value, suite_id: &str) -> Result<(), String> {
    let tf_key = hex_field(row, "twofish_key_hex")?;
    let serpent_key = hex_field(row, "serpent_key_hex")?;
    let iv: [u8; 16] = hex_field(row, "ctr_iv_hex")?
        .try_into()
        .map_err(|_| "ctr_iv_hex: expected 16 bytes".to_string())?;
    let aad = hex_field(row, "aad_hex")?;
    let pt = hex_field(row, "plaintext_hex")?;
    let exp_mid = hex_field(row, "twofish_ciphertext_hex")?;
    let exp_outer = hex_field(row, "outer_ciphertext_hex")?;
    let poly_k = hex32(row, "poly1305_key_hex")?;
    let exp_tag = hex_field(row, "outer_tag_hex")?;
    if exp_tag.len() != 16 {
        return Err("outer_tag_hex: expected 16 bytes".into());
    }
    let mut mid = pt.clone();
    twofish256_ctr_xor(&tf_key, &iv, &mut mid);
    if mid != exp_mid {
        return Err(format!("{suite_id}: Twofish layer mismatch"));
    }
    let mut outer = mid.clone();
    serpent256_ctr_xor(&serpent_key, &iv, &mut outer);
    if outer != exp_outer {
        return Err(format!("{suite_id}: Serpent outer mismatch"));
    }
    let tag = poly1305_tag_rfc8439(&poly_k, &aad, &outer);
    if tag.as_slice() != exp_tag.as_slice() {
        return Err(format!("{suite_id}: outer Poly1305 tag mismatch"));
    }
    Ok(())
}

fn verify_triple_row(row: &toml::Value, suite_id: &str) -> Result<(), String> {
    let chacha_key = hex32(row, "chacha_key_hex")?;
    let nonce: [u8; 12] = hex_field(row, "chacha_nonce_hex")?
        .try_into()
        .map_err(|_| "chacha_nonce_hex: expected 12 bytes".to_string())?;
    let serpent_key = hex_field(row, "serpent_key_hex")?;
    let tf_key = hex_field(row, "twofish_key_hex")?;
    let iv: [u8; 16] = hex_field(row, "ctr_iv_hex")?
        .try_into()
        .map_err(|_| "ctr_iv_hex: expected 16 bytes".to_string())?;
    let aad = hex_field(row, "aad_hex")?;
    let pt = hex_field(row, "plaintext_hex")?;
    let exp_inner1 = hex_field(row, "inner_ciphertext_hex")?;
    let exp_inner2 = hex_field(row, "middle_ciphertext_hex")?;
    let exp_outer = hex_field(row, "outer_ciphertext_hex")?;
    let poly_k = hex32(row, "poly1305_key_hex")?;
    let exp_tag = hex_field(row, "outer_tag_hex")?;
    if exp_tag.len() != 16 {
        return Err("outer_tag_hex: expected 16 bytes".into());
    }
    let inner1 = chacha20_poly1305_encrypt(&chacha_key, &nonce, &aad, &pt);
    if inner1 != exp_inner1 {
        return Err(format!("{suite_id}: ChaCha inner mismatch"));
    }
    let mut inner2 = inner1.clone();
    serpent256_ctr_xor(&serpent_key, &iv, &mut inner2);
    if inner2 != exp_inner2 {
        return Err(format!("{suite_id}: Serpent middle mismatch"));
    }
    let mut outer = inner2.clone();
    twofish256_ctr_xor(&tf_key, &iv, &mut outer);
    if outer != exp_outer {
        return Err(format!("{suite_id}: Twofish outer mismatch"));
    }
    let tag = poly1305_tag_rfc8439(&poly_k, &aad, &outer);
    if tag.as_slice() != exp_tag.as_slice() {
        return Err(format!("{suite_id}: outer Poly1305 tag mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poly1305_matches_serpent_vector_row() {
        let ct = hex::decode("3ae158e636756690d82a74d6a77bd5ca4ea714e78edc2a6794dd5005a7da2bff")
            .unwrap();
        let aad = hex::decode("636573732d6161642d7631").unwrap();
        let poly_k: [u8; 32] = hex::decode("b7346dd7ac30b9132da4f11d8cd19f0fd464f9d5ef51d929bc26244527a3af28")
            .unwrap()
            .try_into()
            .unwrap();
        let expected = hex::decode("ce883d20497e41b431bfdf943f613ba3").unwrap();
        let tag = poly1305_tag_rfc8439(&poly_k, &aad, &ct);
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    #[test]
    fn twofish_ctr_poly1305_kat_single_deterministic() {
        let key = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let iv: [u8; 16] = hex::decode("8de9731f4c821a10c5380e2f111fe632")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = hex::decode("636573732d6161642d7631").unwrap();
        let pt = hex::decode("434553532062756c6b204145414420706c61696e7465787420766563746f722e")
            .unwrap();
        let poly_k: [u8; 32] = hex::decode("b7346dd7ac30b9132da4f11d8cd19f0fd464f9d5ef51d929bc26244527a3af28")
            .unwrap()
            .try_into()
            .unwrap();
        let mut ct = pt.clone();
        twofish256_ctr_xor(&key, &iv, &mut ct);
        let tag = poly1305_tag_rfc8439(&poly_k, &aad, &ct);
        assert_eq!(
            hex::encode(&ct),
            "92220bafb0050d74503f3f5d6fe3ca31f1c3801d0b4357cc926309ff01c84443"
        );
        assert_eq!(hex::encode(tag), "f526ef1866fd4cab9a7b509917405c3c");
    }

    #[test]
    fn cascade_kats_match_bulk_aead_intermediates() {
        let chacha_key: [u8; 32] = hex::decode(
            "fa6859b1082289a751c9ca2501486dd5cf606d564acd178803a2c06ef55b6a47",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let nonce: [u8; 12] = hex::decode("000000000000000000000000").unwrap().try_into().unwrap();
        let tf_outer_key = hex::decode("9d8ab5f5122c5e7c63d48e177a9bbf9aa51b25285f08380c077af96f553f0c61")
            .unwrap();
        let tf_inner_key = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let serpent_outer_key =
            hex::decode("9d8ab5f5122c5e7c63d48e177a9bbf9aa51b25285f08380c077af96f553f0c61").unwrap();
        let iv: [u8; 16] = hex::decode("8de9731f4c821a10c5380e2f111fe632")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = hex::decode("636573732d6161642d7631").unwrap();
        let pt = hex::decode("434553532062756c6b204145414420706c61696e7465787420766563746f722e")
            .unwrap();
        let poly_k: [u8; 32] = hex::decode("b7346dd7ac30b9132da4f11d8cd19f0fd464f9d5ef51d929bc26244527a3af28")
            .unwrap()
            .try_into()
            .unwrap();

        let inner_ct = chacha20_poly1305_encrypt(&chacha_key, &nonce, &aad, &pt);
        let mut ct_ch_tf = inner_ct.clone();
        twofish256_ctr_xor(&tf_outer_key, &iv, &mut ct_ch_tf);
        let tag_ch_tf = poly1305_tag_rfc8439(&poly_k, &aad, &ct_ch_tf);

        let mut mid_tf_s = pt.clone();
        twofish256_ctr_xor(&tf_inner_key, &iv, &mut mid_tf_s);
        let mut ct_tf_s = mid_tf_s.clone();
        serpent256_ctr_xor(&serpent_outer_key, &iv, &mut ct_tf_s);
        let tag_tf_s = poly1305_tag_rfc8439(&poly_k, &aad, &ct_tf_s);

        let inner1 = chacha20_poly1305_encrypt(&chacha_key, &nonce, &aad, &pt);
        let mut inner2 = inner1.clone();
        serpent256_ctr_xor(&serpent_outer_key, &iv, &mut inner2);
        let mut ct_triple = inner2.clone();
        twofish256_ctr_xor(&tf_outer_key, &iv, &mut ct_triple);
        let tag_triple = poly1305_tag_rfc8439(&poly_k, &aad, &ct_triple);

        assert_eq!(hex::encode(&inner_ct), "99b9ef951bc1c9159d42bf037b4872f0bf1bfc52f2e8cfcfa3714b7ddd3d725dab415e055a85439c51838fed7f2f0ca7");
        assert_eq!(
            hex::encode(&ct_ch_tf),
            "fb295f1552207b158396298bcb55938fb88febfdbb326c82084cc181761148cf621f987035da1253549278d46f7babf8"
        );
        assert_eq!(hex::encode(&tag_ch_tf), "3b328596c47ae14b8c66d2d88a0fbe33");
        assert_eq!(
            hex::encode(&mid_tf_s),
            "92220bafb0050d74503f3f5d6fe3ca31f1c3801d0b4357cc926309ff01c84443"
        );
        assert_eq!(
            hex::encode(&ct_tf_s),
            "eb86001aa6121e88e3350ace89dc3f8bd305fd94f1fa05df26c83c99d27d1d92"
        );
        assert_eq!(hex::encode(&tag_tf_s), "1e4c9a4ddd6ca931fd7ff585fe9d12f9");
        let inner1 = chacha20_poly1305_encrypt(&chacha_key, &nonce, &aad, &pt);
        let mut inner2 = inner1.clone();
        serpent256_ctr_xor(&serpent_outer_key, &iv, &mut inner2);
        assert_eq!(
            hex::encode(&inner2),
            "e01de4200dd6dae92e488a909d77874a9ddd81db08519ddc17da7e1b0e882b8c63802e2b2d7bd66b0e0f92721c474ca1"
        );
        assert_eq!(
            hex::encode(&ct_triple),
            "828d54a0443768e9309c1c182d6a66359a499674418b3e91bce7f4e7a5a4111eaadee85e422487a40b1e654b0c13ebfe"
        );
        assert_eq!(hex::encode(&tag_triple), "e354d9eed605517f2d55014466769f4a");
    }

}
