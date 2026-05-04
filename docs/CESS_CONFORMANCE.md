# CESS conformance (runner and vectors)

This note extends the repository root [`CONFORMANCE.md`](../CONFORMANCE.md) with **implementation-level** detail for the cryptographic runner. Normative claims, procurement language, and listing rules remain in that file and in `spec/CESS-v0.2.md`.

## Inner cascade KATs (HKDF-BLAKE3 labels from Galdralag `cess`)

Cross-ecosystem projects (for example **Galdralag-firmware**) ship **cipher-profile** cascade encryption that uses CESS-style inner HKDF-BLAKE3 `info` strings (`crates/cess/src/inner_info.rs`) and **HMAC-BLAKE3** inter-layer tags between inner AEAD outputs and outer encrypt steps (`crates/cipher-profile/src/cascade.rs`). The canonical numeric examples live in:

`cipher-profile/tests/fixtures/cascade_cess_kat.json`

The CESS repository mirrors a subset of those rows as TOML so **`cess-runner`** can verify the same byte strings **without** depending on the firmware workspace.

| Artifact | Role |
|----------|------|
| [`vectors/inner_cascade.toml`](../vectors/inner_cascade.toml) | One row each for `suite_id` **0x0001** (single ChaCha20-Poly1305), **0x0003**, and **0x0012** (ChaCha inner, inter-layer MAC, Serpent outer); field values match `cascade_cess_kat.json` schema_version 1. |
| [`runner/src/inner_cascade.rs`](../runner/src/inner_cascade.rs) | Parses the TOML, derives keys with **HKDF-BLAKE3** (empty salt) and the same UTF-8 `info` builders as `inner_info.rs`, runs **ChaCha20-Poly1305** for layer 0, computes **HMAC-BLAKE3** on `cess-blake3-integrity-{hex}` \|\| inner ciphertext for the gap after layer 0, and checks the **intermediate_before_outer** blob. |

### Gap: cess-runner and inner cascade profile KATs (addressed)

**Previous gap:** `cess-runner` exercised Twofish and legacy **Poly1305** cascade material in `vectors/twofish.toml` and **Poly1305** Serpent rows in `vectors/bulk_aead.toml`, but did not load the **cipher-profile** JSON that locks **HKDF-BLAKE3 `info` suffixes** (`-l0-key`, `-l1-serpent256`, `cess-blake3-integrity-{hex}-gap-l0`, etc.) or the **HMAC-BLAKE3** step between ChaCha and Serpent.

**Current state:** `verify_inner_cascade_toml` is part of `cess_runner::verify_all_crypto_vectors`. The **0x0001** row is **fully** recomputed in the runner (ChaCha with profile **AAD** on the only layer). The **0x0003** and **0x0012** rows recompute **inner ChaCha** (empty **AAD** on layer 0), the **32-byte HMAC-BLAKE3** inter-layer tag, and assert equality with **intermediate_before_outer_hex**.

### Outer Serpent EtM (reference: HMAC-SHA256 tag)

The reference **vault** Serpent profile uses **Serpent-256-CTR** followed by a **32-byte HMAC-SHA256** tag over `aad || nonce || ciphertext_body`. CESS `CONTRIBUTING.md` excludes **SHA-256** for protocol verification in this runner; **`cess-runner` does not instantiate HMAC-SHA256.**

For **0x0003** and **0x0012**, the runner therefore:

1. Recomputes the **Serpent-256-CTR keystream** using the **HKDF-BLAKE3**-derived cipher key and nonce (`cess-inner-{suite}-l1-nonce`, first **16** bytes of the **32-byte** expand), with a **128-bit big-endian** counter increment matching `crates/vault/src/serpent_cipher.rs`.
2. Verifies the **CTR ciphertext body** matches the reference wire image up to but **not including** the trailing **32-byte** tag.
3. Treats the **tag** as **not re-derived in-tree**; full bit-for-bit outer verification is the responsibility of implementations that intentionally include SHA-256 (or of cross-checking against **cipher-profile** / **vault** tests).

This gives **independent** verification of **HKDF labels**, **inner AEAD**, **inter-layer HMAC-BLAKE3**, and **Serpent CTR** compatibility with the reference, while staying aligned with the repository’s **SHA-2 exclusion** policy for `runner/`.

### Regenerating reference JSON

From the **Galdralag-firmware** tree:

```text
cargo run -p cipher-profile --bin cascade-kat-gen > crates/cipher-profile/tests/fixtures/cascade_cess_kat.json
```

After updating that file, copy the shared `ikm_hex`, `aad_hex`, `plaintext_hex`, and per-row `expected_ciphertext_hex` / `intermediate_before_outer_hex` fields into `vectors/inner_cascade.toml` and run `cargo test` in `runner/`.
