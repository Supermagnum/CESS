//! Ed25519 inner-profile signing (`spec/CESS-v0.2.md` Section 4.5).

use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// Verify every `[[vectors]]` row in `ed25519_signing.toml`.
pub fn verify_ed25519_signing_toml(toml_str: &str) -> Result<(), String> {
    let root: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("ed25519_signing.toml parse: {e}"))?;
    let arr = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "ed25519_signing.toml: missing vectors array".to_string())?;
    for (i, row) in arr.iter().enumerate() {
        let kind = row
            .get("case_kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("vectors[{i}]: missing case_kind"))?;
        let sk_bytes: [u8; 32] = hex::decode(
            row.get("ed25519_private_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing ed25519_private_key_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] sk: {e}"))?
        .try_into()
        .map_err(|_| format!("vectors[{i}]: ed25519_private_key_hex must be 32 bytes"))?;
        let pk_bytes: [u8; 32] = hex::decode(
            row.get("ed25519_public_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing ed25519_public_key_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] pk: {e}"))?
        .try_into()
        .map_err(|_| format!("vectors[{i}]: ed25519_public_key_hex must be 32 bytes"))?;

        let exp_sig = hex::decode(
            row.get("expected_signature_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("vectors[{i}]: missing expected_signature_hex"))?,
        )
        .map_err(|e| format!("vectors[{i}] expected_signature_hex: {e}"))?;
        if exp_sig.len() != 64 {
            return Err(format!(
                "vectors[{i}]: expected_signature_hex must be 64 bytes"
            ));
        }

        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = VerifyingKey::from(&signing_key);
        if verifying_key.to_bytes() != pk_bytes {
            return Err(format!(
                "vectors[{i}]: ed25519_public_key_hex does not match private key (expected derived pubkey)"
            ));
        }

        match kind {
            "sign_and_verify_ok" | "rfc8032_empty_message" | "suite_id_inner_blob" => {
                let message = hex::decode(
                    row.get("message_hex")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("vectors[{i}]: missing message_hex"))?,
                )
                .map_err(|e| format!("vectors[{i}] message_hex: {e}"))?;
                let sig = signing_key.sign(&message);
                if sig.to_bytes().as_slice() != exp_sig.as_slice() {
                    return Err(format!(
                        "vectors[{i}]: signature mismatch (recomputed vs expected)"
                    ));
                }
                let sig_typed = Signature::from_slice(&exp_sig)
                    .map_err(|e| format!("vectors[{i}]: invalid signature bytes: {e}"))?;
                verifying_key
                    .verify(&message, &sig_typed)
                    .map_err(|_| format!("vectors[{i}]: Ed25519 verify failed"))?;
            }
            "mode_a_plaintext_layout" => {
                let suite_id_bytes = hex::decode(
                    row.get("suite_id_bytes_hex")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("vectors[{i}]: missing suite_id_bytes_hex"))?,
                )
                .map_err(|e| format!("vectors[{i}] suite_id_bytes_hex: {e}"))?;
                if suite_id_bytes.len() != 2 {
                    return Err(format!("vectors[{i}]: suite_id_bytes_hex must be 2 bytes"));
                }
                let inner_blob = hex::decode(
                    row.get("inner_blob_hex")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("vectors[{i}]: missing inner_blob_hex"))?,
                )
                .map_err(|e| format!("vectors[{i}] inner_blob_hex: {e}"))?;
                let mut message = Vec::with_capacity(suite_id_bytes.len() + inner_blob.len());
                message.extend_from_slice(&suite_id_bytes);
                message.extend_from_slice(&inner_blob);
                let sig = signing_key.sign(&message);
                if sig.to_bytes().as_slice() != exp_sig.as_slice() {
                    return Err(format!(
                        "vectors[{i}]: signature mismatch (recomputed vs expected)"
                    ));
                }
                let sig_typed = Signature::from_slice(&exp_sig)
                    .map_err(|e| format!("vectors[{i}]: invalid signature bytes: {e}"))?;
                verifying_key
                    .verify(&message, &sig_typed)
                    .map_err(|_| format!("vectors[{i}]: Ed25519 verify failed"))?;
                let mode_a = hex::decode(
                    row.get("mode_a_plaintext_hex")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("vectors[{i}]: missing mode_a_plaintext_hex"))?,
                )
                .map_err(|e| format!("vectors[{i}] mode_a_plaintext_hex: {e}"))?;
                let mut expected = suite_id_bytes.clone();
                expected.extend_from_slice(&exp_sig);
                expected.extend_from_slice(&inner_blob);
                if mode_a != expected {
                    return Err(format!(
                        "vectors[{i}]: mode_a_plaintext_hex does not match suite_id || sig || inner_blob"
                    ));
                }
            }
            "verify_fails_tampered_message" => {
                let original = hex::decode(
                    row.get("original_message_hex")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("vectors[{i}]: missing original_message_hex"))?,
                )
                .map_err(|e| format!("vectors[{i}] original_message_hex: {e}"))?;
                let tampered = hex::decode(
                    row.get("tampered_message_hex")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("vectors[{i}]: missing tampered_message_hex"))?,
                )
                .map_err(|e| format!("vectors[{i}] tampered_message_hex: {e}"))?;
                let sig_check = signing_key.sign(&original);
                if sig_check.to_bytes().as_slice() != exp_sig.as_slice() {
                    return Err(format!(
                        "vectors[{i}]: recomputed signature does not match expected_signature_hex"
                    ));
                }
                let sig_typed = Signature::from_slice(&exp_sig)
                    .map_err(|e| format!("vectors[{i}]: invalid signature bytes: {e}"))?;
                if verifying_key.verify(&tampered, &sig_typed).is_ok() {
                    return Err(format!(
                        "vectors[{i}]: expected verification failure on tampered message"
                    ));
                }
            }
            _ => return Err(format!("vectors[{i}]: unknown case_kind {kind}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8032_empty_message_signature_matches_vector() {
        let sk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b3260917032f8d224177b9c")
            .unwrap();
        let sk32: [u8; 32] = sk.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&sk32);
        let vk = VerifyingKey::from(&signing_key);
        assert_eq!(
            hex::encode(vk.to_bytes()),
            "d03f454414e073f17fc982ff1435b3dc7086ae89da1d4c48f69c6a3fde752a7c"
        );
        let sig = signing_key.sign(b"");
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "55027091ae32be5355de1407902897a2780e5dcaf78c8b3e76cce0fc7a095630687e8abd1741484820167093d5e56e95166dd6c6971a5e398978c936d24b080a"
        );
    }
}
