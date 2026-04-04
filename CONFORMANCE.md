# CESS conformance

This document explains how implementations may **claim conformance** to CESS and how they may be **listed** publicly.

## Conformance levels

| Level | Name | Summary |
|-------|------|---------|
| 1 | **CESS-CORE** | Fixed layer (GF(2^8) Shamir, Argon2id, BLAKE3) + ChaCha20-Poly1305 + HKDF-BLAKE3 + Brainpool ECDH profile |
| 2 | **CESS-FULL** | CESS-CORE + Reed–Solomon erasure profile + Serpent cascade option + hardware token profile features |
| 3 | **CESS-PQ** | CESS-FULL + hybrid PQ KEM (FrodoKEM-1344 or Classic McEliece 6688128) with HKDF-BLAKE3 combiner |

Normative detail: `spec/CESS-v0.1.md` Section 12.

## Self-certification

1. Select a conformance **level** you implement completely (no partial claims for mandatory sections).  
2. Run the **test runner** (`runner/`) against your implementation with `--level` set appropriately and `--vectors` pointing at this repository’s `vectors/` directory.  
3. Archive logs showing **PASS** for all **required** vectors for that level (see `vectors/README.md`).  
4. Publish a short **conformance statement** naming the CESS version (e.g. `0.1-draft`), level, and commit hash of vectors used.

## Required vectors per level

- **CESS-CORE:** `sss.toml`, `argon2id.toml`, `blake3.toml`, `hkdf_blake3.toml`, `ecdh_brainpool.toml`, `bulk_aead.toml` (ChaCha rows), `pin_wrap.toml` (ChaCha row), `rejection.toml`, `integration.toml` (ChaCha-only integration rows), `wycheproof_chacha.toml` (subset; full Wycheproof coverage is via `wycheproof_chacha` + JSON), `rfc6932_brainpool.toml` (RFC 6932 IKE ECDH excerpts; full JSON + `scripts/rfc6932_brainpool.py`), `rfc7027_brainpool.toml` (RFC 7027 TLS ECDH excerpts; full JSON + `scripts/rfc7027_brainpool.py`), `rfc5639_brainpool.toml` (RFC 5639 domain-parameter excerpts; JSON + `scripts/rfc5639_brainpool_domain_parameters.py`).  
- **CESS-FULL:** all CORE vectors plus `reed_solomon.toml`, Serpent and cascade rows in `bulk_aead.toml`, Serpent row in `pin_wrap.toml`, hardware-related checks as specified in the standard.  
- **CESS-PQ:** all FULL vectors plus PQ-specific tests when published (see `spec/CESS-v0.1.md` Section 7).

## Listing implementations

Open a pull request editing [`IMPLEMENTATIONS.md`](IMPLEMENTATIONS.md) with:

- Product or library name and URL  
- CESS level claimed  
- Vector commit hash and runner version  
- Contact or security policy link  

Maintainers MAY reject listings that appear misleading or incomplete.

## Trademark and naming

**CESS** is used as a **descriptive** project name. There is **no trademark grant** in the specification or licences. You MAY say “compatible with CESS v0.1” if your statement is accurate and backed by tests. Do not imply endorsement by contributors or maintainers without their written permission.

## What conformance does not mean

Conformance to CESS does **not** certify:

- Correctness of **operational security** (key ceremony, personnel, physical security);  
- **Certification** under any government scheme (Common Criteria, FIPS, etc.) unless separately obtained;  
- **Freedom from patent** or other IP disputes — see `PATENTS.md`.
