//! End-to-end: `vectors/twofish.toml` KATs and `suite_id` coverage for registry rows 0x0004-0x0007 and 0x0203-0x0207.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

#[test]
fn twofish_toml_verifies_against_runner_crypto() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/twofish.toml");
    let s = fs::read_to_string(&path).expect("read twofish.toml");
    cess_runner::twofish_bulk::verify_twofish_toml(&s).expect("verify_twofish_toml");
}

#[test]
fn twofish_toml_suite_ids_match_registry_twofish_rows() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/twofish.toml");
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
        "0x0004", "0x0005", "0x0006", "0x0007", "0x0203", "0x0204", "0x0205", "0x0206",
        "0x0207",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(ids, expected, "expected one KAT per Twofish-related suite_id row");
}
