# Contributing to CESS

Thank you for helping improve the CESS specification and conformance artefacts.

**Style and process (including AI-assisted work):** see [`STYLE-GUIDE.md`](STYLE-GUIDE.md).

## Patent covenant

By opening a pull request that is merged into this repository, you agree to the **patent non-assertion covenant** in [`PATENTS.md`](PATENTS.md). If you cannot agree, do not contribute code or normative text here.

## Specification changes

- **Two reviewers** MUST approve substantive specification edits.  
- Those two reviewers MUST be **affiliated with organisations in different countries** (nationality is not decisive; organisational seat and conflict-of-interest rules apply).  
- Editorial fixes (typos, formatting) MAY be handled with a single reviewer at maintainers’ discretion.

## Algorithm and registry changes

- New or updated algorithms MUST go through [`ALGORITHM-REGISTRY.md`](ALGORITHM-REGISTRY.md): evidence of **two qualifying audits**, exclusion checks, and identifier assignment.  
- Normative references in `spec/CESS-v0.2.md` MUST stay consistent with the registry.

## Test vectors

- Vectors MUST use the TOML schemas under `vectors/` and include **edge cases** (empty inputs, boundary lengths, rejection cases).  
- Hex MUST be **lowercase** with **deterministic** values (no `TODO` placeholders).  
- Prefer extending `scripts/generate_vectors.py` (or documented generation) so vectors remain reproducible.  
- After changing **`vectors/twofish.toml`**, run **`cargo test`** in **`runner/`** so Twofish KAT checks (`verify_twofish_toml`) still pass.

## Test runner dependencies

The conformance runner (`runner/`) MUST **not** invoke algorithms on the **CESS exclusion list** (AES, SHA-2, SHA-3, HMAC-SHA-*, NIST curves, ML-KEM, and so on) for **protocol verification**. **Transitive** crates pulled by **approved** cryptographic libraries MUST NOT be used as CESS protocol primitives (e.g. HKDF-BLAKE3 and BLAKE3 only for hashing/KDF). The `p384` crate was therefore omitted from the runner manifest because it pulls SHA-256-family code; Brainpool ECDH verification is exercised against `vectors/ecdh_brainpool.toml` using an implementation under test. The `vsss-rs` crate was omitted because it pulls SHA-256-family crates; GF(2^8) Shamir checks use the same arithmetic as `scripts/generate_vectors.py`.

## Code of conduct

Participants MUST behave professionally: harassment and personal attacks are not tolerated. Maintainers may remove or block contributors who violate these expectations.

## Security issues

Report suspected vulnerabilities in cryptographic constructions or reference code through a **private** channel if offered by maintainers; otherwise open a confidential security advisory per platform defaults.
