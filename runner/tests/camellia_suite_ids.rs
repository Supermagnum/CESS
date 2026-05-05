//! End-to-end: `vectors/camellia.toml` KATs and `suite_id` coverage for Camellia registry rows.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

#[test]
fn camellia_toml_verifies_against_runner_crypto() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/camellia.toml");
    let s = fs::read_to_string(&path).expect("read camellia.toml");
    cess_runner::camellia_bulk::verify_camellia_toml(&s).expect("verify_camellia_toml");
}

#[test]
fn camellia_toml_suite_ids_match_registry_camellia_rows() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/camellia.toml");
    let s = fs::read_to_string(&path).unwrap();
    let root: toml::Value = s.parse().unwrap();
    let arr = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .expect("vectors array");
    let mut ids = BTreeSet::new();
    for row in arr {
        let id = row
            .get("suite_id")
            .and_then(|v| v.as_str())
            .expect("suite_id");
        ids.insert(id.to_string());
    }
    let expected: BTreeSet<String> = [
        "0x0031", "0x0032", "0x0033", "0x0034", "0x0035", "0x0036", "0x0208", "0x0209",
        "0x020a", "0x020b", "0x020c",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(ids, expected, "expected one KAT per Camellia suite_id row");
}
