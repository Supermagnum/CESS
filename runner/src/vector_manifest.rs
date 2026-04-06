//! `vectors/classical_suite_id_matrix.toml` admission checks.

/// Every provisional row must reference a vector file/entry or a pending issue URL.
pub fn verify_classical_suite_matrix_toml(toml_str: &str) -> Result<(), String> {
    let root: toml::Value = toml_str
        .parse()
        .map_err(|e| format!("classical_suite_id_matrix.toml parse: {e}"))?;
    let arr = root
        .get("suite_ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "classical_suite_id_matrix.toml: missing suite_ids array".to_string())?;
    for (i, row) in arr.iter().enumerate() {
        let status = row
            .get("status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("suite_ids[{i}]: missing status"))?;
        if status != "provisional" {
            continue;
        }
        let has_vector = row.get("vector_file").and_then(|v| v.as_str()).is_some()
            || row.get("vector_entry").and_then(|v| v.as_str()).is_some();
        let pending = row.get("pending_issue").and_then(|v| v.as_str()).is_some();
        if !has_vector && !pending {
            let sid = row
                .get("suite_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            return Err(format!(
                "suite_ids[{i}] {sid}: provisional row needs vector_file/vector_entry or pending_issue"
            ));
        }
    }
    Ok(())
}
