# CESS test vectors

Machine-readable vectors use **TOML** with `[[vectors]]` and `[[rejection_cases]]` array tables where applicable. All cryptographic values are **lowercase hexadecimal** unless noted.

## Schemas

Each file begins with a `schema` key identifying the format revision, e.g. `cess-sss-v0.1`.

## How to use

1. Load the appropriate `.toml` file for the subsystem under test.  
2. For each `[[vectors]]` entry, run the operation under test with `description` as human context.  
3. Compare outputs to the `*_hex` expected fields.  
4. For `rejection_cases`, assert the implementation returns the listed `expected_error` code (see `spec/CESS-v0.1.md` Section 14).

## Conformance levels

| File | CORE | FULL | PQ |
|------|------|------|-----|
| `sss.toml` | yes | yes | yes |
| `blake3.toml` | yes | yes | yes |
| `argon2id.toml` | yes | yes | yes |
| `hkdf_blake3.toml` | yes | yes | yes |
| `ecdh_brainpool.toml` | yes | yes | yes |
| `bulk_aead.toml` | ChaCha rows | + Serpent + cascade | + PQ when added |
| `pin_wrap.toml` | ChaCha row | + Serpent row | optional |
| `reed_solomon.toml` | no | yes | yes |
| `rejection.toml` | yes | yes | yes |
| `integration.toml` | partial rows | + cascade row | + PQ when added |
| `wycheproof_chacha.toml` | informative cross-check | same | same |
| `rfc6932_brainpool.toml` | informative cross-check | same | same |
| `rfc7027_brainpool.toml` | informative cross-check | same | same |
| `rfc5639_brainpool.toml` | informative cross-check | same | same |

## RFC 5639 (domain parameters)

Canonical **p, a, b, G, q, h** for brainpoolP256r1 / P384r1 / P512r1 are in `testdata/rfc5639/rfc5639_brainpool_domain_parameters.json`. OpenSSL cross-check:

```bash
.venv/bin/python scripts/rfc5639_brainpool_domain_parameters.py
```

**BSI TR-03111** defines ECC profiles and official test material; vectors are not reproduced here (PDF). Field-element encoding for ECDH follows **SEC1** as referenced by RFC 7027.

## RFC 7027 (TLS Brainpool ECDH, Appendix A)

Known-answer **TLS** ECDH vectors (pre-master secret = **x_Z**) for P-256, P-384, P-512: `testdata/rfc7027/rfc7027_brainpool_tls_ecdh.json`. These differ numerically from RFC 6932 for the same curve names.

```bash
.venv/bin/python scripts/rfc7027_brainpool.py
cd runner && env -u CARGO_TARGET_DIR cargo run --release --bin rfc6932_brainpool -- ../testdata/rfc7027/rfc7027_brainpool_tls_ecdh.json
```

## RFC 6932 (Brainpool ECDH, Appendix A)

CESS vendors **IETF RFC 6932** Appendix A hex at `testdata/rfc6932/rfc6932_brainpool_ecdh.json`. The script `scripts/rfc6932_brainpool.py` checks **all four** curves (P-224 uses **OpenSSL**; P-256/384/512 use **cryptography**). The Rust binary `rfc6932_brainpool` checks **P-256 and P-384** against `bp256` / `bp384`.

```bash
.venv/bin/python scripts/rfc6932_brainpool.py
cd runner && env -u CARGO_TARGET_DIR cargo run --release --bin rfc6932_brainpool -- ../testdata/rfc6932/rfc6932_brainpool_ecdh.json
```

## Wycheproof (ChaCha20-Poly1305)

CESS vendors the **C2SP Wycheproof** JSON at `testdata/wycheproof/chacha20_poly1305_test.json` (Apache-2.0). The Rust tool `runner` / `wycheproof_chacha` runs **all** cases against `chacha20poly1305` (must report `fail=0`).

The TOML file `wycheproof_chacha.toml` holds a **small subset** plus metadata so CESS documentation references the same hex values as Wycheproof for the primary AEAD.

```bash
cd runner && cargo run --release --bin wycheproof_chacha -- ../testdata/wycheproof/chacha20_poly1305_test.json
```

## Contributing vectors

- Add a `description` to every table.  
- Use **deterministic** inputs; document PRNG seeds if used.  
- Extend `scripts/generate_vectors.py` when possible.  
- Serpent-dependent vectors require `scripts/serpent_helper` built with `cargo build --release --target-dir ./target`.

## Regenerating vectors

From repository root:

```bash
python3 -m venv .venv && .venv/bin/pip install cryptography blake3 argon2-cffi pycryptodome
cd scripts/serpent_helper && cargo build --release --target-dir ./target && cd ../..
.venv/bin/python scripts/generate_vectors.py
```
