# CESS Algorithm Registry (living document)

**Version:** 0.2-draft  
**Maintainers:** CESS editorial board (repository maintainers)

This registry records **approved**, **excluded**, and **provisional** algorithms for cipher-agnostic CESS layers. The **normative** rules appear in `spec/CESS-v0.2.md` Section 3; this file is the **operational** checklist for pull requests.

## Admission criteria (all MUST hold)

1. **Two independent audits** from the qualifying auditor list in the specification (same paper team counts once for IACR work).  
2. **No NSA design input** for symmetric primitives; **no reliance on NIST/FIPS-only** review as the sole evidence.  
3. **No entry** on the **hard exclusion list** unless explicitly listed as “optional permitted” with rationale (currently X25519/Ed25519 only).  
4. **Interop**: a **cipher suite identifier** can be allocated without collision (Section 14). Identifiers are **not** on-wire cleartext framing; see `spec/CESS-v0.2.md` Section 8.1 and 8.5.  
5. **Documentation**: audit citations with **version**, **date**, and **link** or stable identifier.  
6. **Test vectors**: at least one vector file updated in `vectors/` before “approved” status.  
7. **PQ-specific**: post-quantum algorithms MUST document **classical + PQ hybrid** behaviour with HKDF-BLAKE3 per `spec/CESS-v0.2.md` Section 7.

## Current approved algorithms

| Component | Algorithm | Audit evidence (examples) | Notes |
|-----------|-----------|-----------------------------|-------|
| Secret sharing | Shamir over GF(2^8), threshold k-of-n | Mathematical literature; see `spec/CRYPTO.md` | Fixed layer; not selectable |
| Password hash | Argon2id (RFC 9106) | PHC winner; Kudelski, Aumasson analyses | Fixed profile in spec |
| Integrity | BLAKE3 | NCC Group, Kudelski | Fixed layer |
| Classical KEM | BrainpoolP384r1 / BrainpoolP512r1 ECDH | RFC 5639; BSI TR-03111 | Point validation required |
| Outer session ECDH (Mode A) | **BrainpoolP384r1** ECDH **only** | RFC 5639; BSI TR-03111 | Mandatory for `K_outer` establishment; see `spec/CESS-v0.2.md` Section 6.1.1 |
| KDF | HKDF-BLAKE3 (RFC 5869 structure, HMAC-BLAKE3) | BLAKE3 paper; HKDF analysis | `info` strings in spec |
| AEAD (primary) | ChaCha20-Poly1305 (RFC 8439) | eSTREAM / extensive review | Primary bulk AEAD |
| AEAD (alt) | Serpent-256-CTR + Poly1305 | NESSIE Serpent; Poly1305 literature | Cascade-capable |
| Erasure coding | Reed–Solomon over GF(2^8) (profile in spec) | Classical RS literature | Data shards, not key shards |
| PQ KEM (primary) | FrodoKEM-1344 | NCC Group report (specify version in implementation) | Hybrid only |
| PQ KEM (alt) | Classic McEliece 6688128 | Long-standing code-based literature | Hybrid only |

## Current excluded algorithms

| Algorithm | Rationale |
|-----------|-----------|
| AES (any mode) | NSA-designed S-box |
| SHA-2 family | NSA-designed |
| SHA-3 / Keccak | NSA competition involvement (informative historical note) |
| P-256, P-384, P-521 | NIST/NSA curves |
| ML-KEM / Kyber | NIST PQC process exclusion per CESS policy |
| Dual_EC_DRBG | Known backdoor |
| RC4, DES, 3DES | Broken or NSA-tainted |
| HMAC-SHA-* | Inherits SHA-2 exclusion |

## Optional permitted (explicit rationale required in deployments)

| Algorithm | Rationale summary |
|-----------|-------------------|
| X25519, Ed25519 | Bernstein designs; extensive independent cryptanalysis; NIST later adoption does not negate prior audits |

## Provisional listings

Algorithms **under review** for full approval. Implementers MAY ship them only when labelled **experimental** and when **CESS-PQ** or registry text explicitly allows.

| Algorithm | Status | Next review gate |
|-----------|--------|-------------------|
| FrodoKEM-1344 | Provisional | Maintainer sign-off + vector stability |
| Classic McEliece 6688128 | Provisional | Maintainer sign-off + vector stability |

## Review process

1. Author opens a PR updating this file and (if normative) `spec/CESS-v0.2.md`.  
2. **Two maintainers** in **different countries** MUST approve (same rule as spec).  
3. CI MUST run vector and runner checks when code is touched.  
4. **Merge** adds the algorithm to **approved** or moves provisional to **approved**.

## Provisional listing process

- Use when audits exist but vectors or identifier allocation are incomplete.  
- Mark **provisional** with an **expiry date** (suggested: 12 months) after which the entry is **removed** or **promoted**.

## Removal process

If a break or catastrophic weakness is confirmed:

1. Move entry to **removed** subsection with **CVE** or paper reference.  
2. Bump **share format** or **suite version** if interoperability is affected.  
3. Issue **security advisory** in the repository.

## Cipher suite identifier assignment

- **16-bit** values `0x0000`–`0xFFFF` are **registry** codes for implementations, documentation, **off-wire** negotiation, and **authenticated plaintext** inside **Mode A** outer envelopes (`spec/CESS-v0.2.md` Section 8.3). They are **not** transmitted in **cleartext** as message framing; third parties without session keys **MUST NOT** be able to read them from the wire (Section 8.1).  
- `0x0000` is **reserved**; envelopes carrying `suite_id = 0x0000` in outer plaintext MUST be **rejected** (Section 14.2).  
- Assignments are **first-come** in PRs that include rationale and vectors.  
- Maintainers maintain the **canonical table** in `spec/CESS-v0.2.md` Appendix or Section 8.5.

## Version history

| Date | Change |
|------|--------|
| 2026-04-04 | Initial 0.1-draft registry |
| 2026-04-04 | Clarify suite IDs are not cleartext framing; align with `spec/CESS-v0.2.md` Section 8 |
| 2026-04-04 | Register mandatory **BrainpoolP384r1** for **Mode A** outer session ECDH (Section 6.1.1) |
| 2026-04-04 | **0.2-draft:** normative specification file is `spec/CESS-v0.2.md` |
