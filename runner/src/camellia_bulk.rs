//! Camellia-128/192/256-CTR + Poly1305 (RFC 8439 MAC layout), matching bulk AEAD Serpent/Twofish profiles.
//! CTR increment matches `twofish_bulk` / `vectors/twofish.toml` (16-byte little-endian counter schedule).

use camellia::{Camellia128, Camellia192, Camellia256};
use cipher::array::Array;
use cipher::consts::U16;
use cipher::{Block, BlockCipherEncrypt, Key, KeyInit};
use crate::twofish_bulk::{
    chacha20_poly1305_encrypt, poly1305_tag_rfc8439, serpent256_ctr_xor,
};

/// Camellia-CTR: encrypt or decrypt `buf` in place (CTR XOR). `key` must be **16**, **24**, or **32** bytes.
pub fn camellia_ctr_xor(key: &[u8], iv16: &[u8; 16], buf: &mut [u8]) {
    match key.len() {
        16 => camellia128_ctr_xor_inner(key, iv16, buf),
        24 => camellia192_ctr_xor_inner(key, iv16, buf),
        32 => camellia256_ctr_xor_inner(key, iv16, buf),
        _ => panic!("Camellia key must be 16, 24, or 32 bytes"),
    }
}

fn camellia128_ctr_xor_inner(key: &[u8], iv16: &[u8; 16], buf: &mut [u8]) {
    let ka = Key::<Camellia128>::try_from(key).expect("Camellia-128 key");
    let cipher = Camellia128::new(&ka);
    let mut ctr = *iv16;
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut block = Block::<Camellia128>::from(Array::<u8, U16>::from(ctr));
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

fn camellia192_ctr_xor_inner(key: &[u8], iv16: &[u8; 16], buf: &mut [u8]) {
    let ka = Key::<Camellia192>::try_from(key).expect("Camellia-192 key");
    let cipher = Camellia192::new(&ka);
    let mut ctr = *iv16;
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut block = Block::<Camellia192>::from(Array::<u8, U16>::from(ctr));
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

fn camellia256_ctr_xor_inner(key: &[u8], iv16: &[u8; 16], buf: &mut [u8]) {
    let ka = Key::<Camellia256>::try_from(key).expect("Camellia-256 key");
    let cipher = Camellia256::new(&ka);
    let mut ctr = *iv16;
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut block = Block::<Camellia256>::from(Array::<u8, U16>::from(ctr));
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

/// Verify every `[[vectors]]` row in `vectors/camellia.toml`.
pub fn verify_camellia_toml(toml_str: &str) -> Result<(), String> {
    let root: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("camellia.toml parse: {e}"))?;
    let arr = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "camellia.toml: missing vectors array".to_string())?;
    for (i, row) in arr.iter().enumerate() {
        let suite_id = row
            .get("suite_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing suite_id"))?;
        match suite_id {
            "0x0031" | "0x0032" | "0x0033" | "0x0208" | "0x020c" => verify_single_row(row, suite_id)?,
            "0x0034" | "0x0209" => verify_chacha_camellia_row(row, suite_id)?,
            "0x0035" | "0x020a" => verify_camellia_serpent_row(row, suite_id)?,
            "0x0036" | "0x020b" => verify_triple_row(row, suite_id)?,
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
    let key = hex_field(row, "camellia_key_hex")?;
    if ![16usize, 24, 32].contains(&key.len()) {
        return Err(format!(
            "{suite_id}: camellia_key_hex must be 16, 24, or 32 bytes"
        ));
    }
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
    if suite_id == "0x020c" {
        let ik = hex32(row, "blake3_integrity_key_hex")?;
        let exp_blake = hex_field(row, "expected_blake3_integrity_tag_hex")?;
        if exp_blake.len() != 32 {
            return Err("expected_blake3_integrity_tag_hex: expected 32 bytes".into());
        }
        let mut blob = exp_ct.clone();
        blob.extend_from_slice(&exp_tag);
        let mut h = blake3::Hasher::new_keyed(&ik);
        h.update(&blob);
        if h.finalize().as_bytes().as_slice() != exp_blake.as_slice() {
            return Err(format!("{suite_id}: keyed BLAKE3 integrity tag mismatch"));
        }
    }
    let mut ct = pt.clone();
    camellia_ctr_xor(&key, &iv, &mut ct);
    if ct != exp_ct {
        return Err(format!("{suite_id}: ciphertext mismatch"));
    }
    let tag = poly1305_tag_rfc8439(&poly_k, &aad, &ct);
    if tag.as_slice() != exp_tag.as_slice() {
        return Err(format!("{suite_id}: Poly1305 tag mismatch"));
    }
    Ok(())
}

fn verify_chacha_camellia_row(row: &toml::Value, suite_id: &str) -> Result<(), String> {
    let chacha_key = hex32(row, "chacha_key_hex")?;
    let nonce: [u8; 12] = hex_field(row, "chacha_nonce_hex")?
        .try_into()
        .map_err(|_| "chacha_nonce_hex: expected 12 bytes".to_string())?;
    let cam_key = hex_field(row, "camellia_key_hex")?;
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
    camellia_ctr_xor(&cam_key, &iv, &mut outer);
    if outer != exp_outer {
        return Err(format!("{suite_id}: outer ciphertext mismatch"));
    }
    let tag = poly1305_tag_rfc8439(&poly_k, &aad, &outer);
    if tag.as_slice() != exp_tag.as_slice() {
        return Err(format!("{suite_id}: outer Poly1305 tag mismatch"));
    }
    Ok(())
}

fn verify_camellia_serpent_row(row: &toml::Value, suite_id: &str) -> Result<(), String> {
    let cam_key = hex_field(row, "camellia_key_hex")?;
    let serpent_key = hex_field(row, "serpent_key_hex")?;
    let iv: [u8; 16] = hex_field(row, "ctr_iv_hex")?
        .try_into()
        .map_err(|_| "ctr_iv_hex: expected 16 bytes".to_string())?;
    let aad = hex_field(row, "aad_hex")?;
    let pt = hex_field(row, "plaintext_hex")?;
    let exp_mid = hex_field(row, "camellia_ciphertext_hex")?;
    let exp_outer = hex_field(row, "outer_ciphertext_hex")?;
    let poly_k = hex32(row, "poly1305_key_hex")?;
    let exp_tag = hex_field(row, "outer_tag_hex")?;
    if exp_tag.len() != 16 {
        return Err("outer_tag_hex: expected 16 bytes".into());
    }
    let mut mid = pt.clone();
    camellia_ctr_xor(&cam_key, &iv, &mut mid);
    if mid != exp_mid {
        return Err(format!("{suite_id}: Camellia layer mismatch"));
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
    let cam_key = hex_field(row, "camellia_key_hex")?;
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
    camellia_ctr_xor(&cam_key, &iv, &mut outer);
    if outer != exp_outer {
        return Err(format!("{suite_id}: Camellia outer mismatch"));
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
    fn camellia_kats_match_camellia_toml_material() {
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

        let k128 = hex::decode("0123456789abcdef0123456789abcdef").unwrap();
        let mut ct = pt.clone();
        camellia_ctr_xor(&k128, &iv, &mut ct);
        assert_eq!(
            hex::encode(&ct),
            "9caf82c7da93b77e17335b7352072d7fb65298a5a16b6414d033dca9a88bcfc1"
        );
        assert_eq!(
            hex::encode(poly1305_tag_rfc8439(&poly_k, &aad, &ct)),
            "b0eb631f9d8570529aff9ec81cf55ce4"
        );

        let k192 =
            hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
        let mut ct = pt.clone();
        camellia_ctr_xor(&k192, &iv, &mut ct);
        assert_eq!(
            hex::encode(&ct),
            "9d0e227f59ecfc55d41348a8d4cf6f2ba16f29179557fa8996b24d213c591f2f"
        );
        assert_eq!(
            hex::encode(poly1305_tag_rfc8439(&poly_k, &aad, &ct)),
            "5bcba7eeac9db66144bca7fc69a78665"
        );

        let k256 = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let mut ct = pt.clone();
        camellia_ctr_xor(&k256, &iv, &mut ct);
        assert_eq!(
            hex::encode(&ct),
            "451bfc962d827870481f53811e7311d4a561a8a9cf3719ac7022d751bca2541b"
        );
        assert_eq!(
            hex::encode(poly1305_tag_rfc8439(&poly_k, &aad, &ct)),
            "314d8e8ed19cf6e2af83515ae9fd55cf"
        );
    }

    #[test]
    fn camellia_cascade_kats_deterministic() {
        use crate::twofish_bulk::{chacha20_poly1305_encrypt, serpent256_ctr_xor};
        let chacha_key: [u8; 32] = hex::decode(
            "fa6859b1082289a751c9ca2501486dd5cf606d564acd178803a2c06ef55b6a47",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let nonce: [u8; 12] = hex::decode("000000000000000000000000").unwrap().try_into().unwrap();
        let cam_outer_key =
            hex::decode("9d8ab5f5122c5e7c63d48e177a9bbf9aa51b25285f08380c077af96f553f0c61").unwrap();
        let cam_inner_key = hex::decode(
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
        let mut oc_ch_cam = inner_ct.clone();
        camellia_ctr_xor(&cam_outer_key, &iv, &mut oc_ch_cam);
        assert_eq!(
            hex::encode(&oc_ch_cam),
            "96a91e369868f0a4b82323e51a98d700af0e89c55d5d8a93c169c3e4c0395cda64aa30a97f4eee99ce8e7294d6f047dc"
        );
        assert_eq!(
            hex::encode(poly1305_tag_rfc8439(&poly_k, &aad, &oc_ch_cam)),
            "7d0aea0c3cfa9a800c71ff25ea067276"
        );

        let mut mid = pt.clone();
        camellia_ctr_xor(&cam_inner_key, &iv, &mut mid);
        let mut oc_cam_s = mid.clone();
        serpent256_ctr_xor(&serpent_outer_key, &iv, &mut oc_cam_s);
        assert_eq!(
            hex::encode(&mid),
            "451bfc962d827870481f53811e7311d4a561a8a9cf3719ac7022d751bca2541b"
        );
        assert_eq!(
            hex::encode(&oc_cam_s),
            "3cbff7233b956b8cfb156612f84ce46e87a7d520358e4bbfc489e2376f170dca"
        );
        assert_eq!(
            hex::encode(poly1305_tag_rfc8439(&poly_k, &aad, &oc_cam_s)),
            "b63302e7f6f8c3de64ef57d5f20f99fe"
        );

        let inner1 = chacha20_poly1305_encrypt(&chacha_key, &nonce, &aad, &pt);
        let mut inner2 = inner1.clone();
        serpent256_ctr_xor(&serpent_outer_key, &iv, &mut inner2);
        let mut outer = inner2.clone();
        camellia_ctr_xor(&cam_outer_key, &iv, &mut outer);
        assert_eq!(
            hex::encode(&outer),
            "ef0d15838e7fe3580b291676fca722ba8dc8f44ca7e4d88075c2f682138c050bac6b408708b07b6e91026f0bb59807da"
        );
        assert_eq!(
            hex::encode(poly1305_tag_rfc8439(&poly_k, &aad, &outer)),
            "f8a2c735b55ffcc0703f5395ccf1f30c"
        );

        let k256 = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let mut ct = pt.clone();
        camellia_ctr_xor(&k256, &iv, &mut ct);
        let tag = poly1305_tag_rfc8439(&poly_k, &aad, &ct);
        let ik: [u8; 32] = hex::decode("1ad3b986e37393a733c64ec806abd28ba33391b3fad1719b3c13cf081d469565")
            .unwrap()
            .try_into()
            .unwrap();
        let mut blob = ct.clone();
        blob.extend_from_slice(&tag);
        let mut h = blake3::Hasher::new_keyed(&ik);
        h.update(&blob);
        assert_eq!(
            hex::encode(h.finalize().as_bytes().as_slice()),
            "357a1913617f243c0052e7c775edcbcbe799e0fd1ac752eec433f4d6d23d0fb4"
        );
    }
}
