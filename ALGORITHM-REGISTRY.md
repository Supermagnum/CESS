# CESS Algorithm Registry (living document)

**Version:** 0.2-draft  
**Last updated:** 2026-04-06  
**Maintainers:** CESS editorial board (repository maintainers)

This registry records **approved**, **excluded**, and **provisional** algorithms for cipher-agnostic CESS layers. The **normative** rules appear in `spec/CESS-v0.2.md` Section 3; this file is the **operational** checklist for pull requests.

## Admission criteria (all MUST hold)

1. **Two independent audits** from the qualifying auditor list in the specification (same paper team counts once for IACR work).  
2. **No NSA design input** for symmetric primitives; **no reliance on NIST/FIPS-only** review as the sole evidence.  
3. **No entry** on the **hard exclusion list** unless explicitly listed as “optional permitted” with rationale (currently X25519/Ed25519 only).  
4. **Interop**: a **cipher suite identifier** can be allocated without collision (`spec/CESS-v0.2.md` Section 14.2 and **Cipher suite identifier assignment** below). Identifiers are **not** on-wire cleartext framing; see `spec/CESS-v0.2.md` Section 8.1 and 8.5.  
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

Normative rules for the **16-bit** value space (range, reserved **`0x0000`**, rejection behaviour) are in **`spec/CESS-v0.2.md` Section 14.2**. This subsection is the operational checklist for registry pull requests.

- **16-bit** values `0x0000`–`0xFFFF` are **registry** codes for implementations, documentation, **off-wire** negotiation, and **authenticated plaintext** inside **Mode A** outer envelopes (`spec/CESS-v0.2.md` Section 8.3). They are **not** transmitted in **cleartext** as message framing; third parties without session keys **MUST NOT** be able to read them from the wire (Section 8.1).  
- `0x0000` is **reserved**; envelopes carrying `suite_id = 0x0000` in outer plaintext MUST be **rejected** (`spec/CESS-v0.2.md` Section 14.2).  
- Assignments are **first-come** in PRs that include rationale and vectors.  
- The **canonical numeric assignment table** is **this file** (**Cipher suite identifier lookup table** below). New rows require a registry PR; do not use unlisted codes for interoperable profiles.

### Cipher suite identifier lookup table

Each row is one **inner** cipher tuple: **`(classical KEM for inner key derivation, optional PQ KEM, HKDF-BLAKE3, bulk AEAD or cascade)`** per `spec/CESS-v0.2.md` Sections 4.2, 6.1, 6.3, 6.6, and 7. **KDF** is always **HKDF-BLAKE3** with suite-specific `info` as in Section 8.3 unless a deployment profile documents an exception. **Mode A** outer framing is fixed (Section 6.6); **`suite_id`** selects only the **inner** profile.

**Normative:** The meaning of each **`suite_id`** **MUST** be taken from the **lookup table** below. If an **informative** bit-field reading **conflicts** with a **lookup table** row, the **lookup table** is **authoritative** (`spec/CESS-v0.2.md` Section 8.5).

**Encoding structure (informative):** The **`suite_id`** value encodes inner profile components in a structured layout to aid implementation:

- **Bits 15–8** (for example **`0x00`** vs **`0x01`** vs **`0x02`**, and so on): **PQ KEM family.** **`0x00xx`** = classical only; **`0x01xx`** = FrodoKEM-1344 hybrid; **`0x011x`** = Classic McEliece 6688128 hybrid; **`0x012x`** = BrainpoolP512r1 + FrodoKEM-1344 hybrid.  
- **Bits 7–4:** Classical inner KEM curve. **`0x_0_`** = BrainpoolP384r1; **`0x_1_`** = BrainpoolP512r1.  
- **Bits 3–0:** Bulk AEAD selection. **`0x__0`** = ChaCha20-Poly1305; **`0x__1`** = Serpent-256-CTR + Poly1305; **`0x__2`** = cascade (ChaCha20-Poly1305 inner, Serpent-256-CTR + Poly1305 outer).

**Informative:** The **`0x011x`** range **lies inside** the **`0x01xx`** span; **FrodoKEM-1344** applies to **`0x01xx`** **except** where **`0x011x`** denotes **Classic McEliece 6688128** per the lookup table. **Reserved** **`0x0000`** and the **lookup table** row for **`0x0001`** (BrainpoolP384r1 + ChaCha20-Poly1305) **preclude** a **pure** low-nibble **`0`** ChaCha code for that default **CESS-CORE** profile; **implementations MUST** still use the **lookup table** for **`0x0001`**.

| `suite_id` | Classical inner KEM | PQ KEM | Bulk AEAD (inner) | Notes |
|------------|----------------------|--------|-------------------|-------|
| `0x0000` | — | — | — | **Reserved**; MUST reject (`spec/CESS-v0.2.md` Section 14.2). |
| `0x0001` | BrainpoolP384r1 | — | ChaCha20-Poly1305 | Default **CESS-CORE** inner profile; with **Mode A**, IKM matches outer ECDH (Section 6.1.1). |
| `0x0002` | BrainpoolP384r1 | — | Serpent-256-CTR + Poly1305 | Single-layer Serpent profile (Section 6.3). |
| `0x0003` | BrainpoolP384r1 | — | Cascade: ChaCha20-Poly1305 inner, Serpent-256-CTR + Poly1305 outer | Default cascade order (Section 4.4). |
| `0x0010` | BrainpoolP512r1 | — | ChaCha20-Poly1305 | Inner classical KEM on **P512**; requires **additional** ECDH or **Mode B** when not sharing **Mode A** P384 IKM (Section 6.1.1). |
| `0x0011` | BrainpoolP512r1 | — | Serpent-256-CTR + Poly1305 | Same IKM caveat as `0x0010`. |
| `0x0012` | BrainpoolP512r1 | — | Cascade: ChaCha20-Poly1305 inner, Serpent-256-CTR + Poly1305 outer | Same IKM caveat as `0x0010`. |
| `0x0100` | BrainpoolP384r1 | FrodoKEM-1344 | ChaCha20-Poly1305 | **CESS-PQ** hybrid IKM (Section 7.2); **provisional** PQ per **Provisional listings** above. |
| `0x0101` | BrainpoolP384r1 | FrodoKEM-1344 | Serpent-256-CTR + Poly1305 | Provisional PQ; same hybrid combiner as Section 7.2. |
| `0x0102` | BrainpoolP384r1 | FrodoKEM-1344 | Cascade: ChaCha inner, Serpent+Poly1305 outer | Provisional PQ. |
| `0x0110` | BrainpoolP384r1 | Classic McEliece 6688128 | ChaCha20-Poly1305 | Provisional PQ. |
| `0x0111` | BrainpoolP384r1 | Classic McEliece 6688128 | Serpent-256-CTR + Poly1305 | Provisional PQ. |
| `0x0112` | BrainpoolP384r1 | Classic McEliece 6688128 | Cascade: ChaCha inner, Serpent+Poly1305 outer | Provisional PQ. |
| `0x0120` | BrainpoolP512r1 | FrodoKEM-1344 | ChaCha20-Poly1305 | Provisional PQ; P512 inner KEM (Section 6.1.1 caveat). |
| `0x0121` | BrainpoolP512r1 | FrodoKEM-1344 | Serpent-256-CTR + Poly1305 | Provisional PQ. |
| `0x0122` | BrainpoolP512r1 | FrodoKEM-1344 | Cascade: ChaCha inner, Serpent+Poly1305 outer | Provisional PQ. |

**Unknown `suite_id` handling (normative):** Implementations MUST treat any **`suite_id`** value **not** listed in **this table** as **unsupported** and MUST **reject** the frame **without** attempting **inner** decryption, **unless** a **deployment-specific private-use agreement** documented **out-of-band** **explicitly authorises** the value. The **rejection** MUST **NOT** reveal which **`suite_id`** was received to any party **other** than a **local administrator log**, to avoid **oracle** attacks on the identifier space. **Outer** ChaCha20-Poly1305 tag **verification** **MUST** succeed **before** **`suite_id`** is **read** or **acted on**; tag **failure** and **unknown** **`suite_id`** **rejection** **MUST** be **indistinguishable** to **remote** parties and **holders** (same **generic** error); **normative** ordering and leakage rules are in **`spec/CESS-v0.2.md`** Sections **8.3** and **8.5**.

**Informative (registry maintenance):** **Unallocated** values include **`0x0004`–`0x000F`**, **`0x0013`–`0x00FF`**, **`0x0103`–`0x010F`**, **`0x0113`–`0x011F`**, **`0x0123`–`0xFFFF`**, and **all gaps** not listed above.

## Version history

| Date | Change |
|------|--------|
| 2026-04-04 | Initial 0.1-draft registry |
| 2026-04-04 | Clarify suite IDs are not cleartext framing; align with `spec/CESS-v0.2.md` Section 8 |
| 2026-04-04 | Register mandatory **BrainpoolP384r1** for **Mode A** outer session ECDH (Section 6.1.1) |
| 2026-04-04 | **0.2-draft:** normative specification file is `spec/CESS-v0.2.md` |
| 2026-04-06 | Add **Cipher suite identifier lookup table** (canonical `suite_id` assignments) |
| 2026-04-06 | Add **informative** `suite_id` bit-field encoding; **normative** lookup precedence (`spec/CESS-v0.2.md` Section 8.5) |
| 2026-04-06 | **Normative** unknown **`suite_id`** handling and oracle/leakage rules (`spec/CESS-v0.2.md` Section 8.5) |
| 2026-04-06 | **Normative** outer **Poly1305**-before-**`suite_id`** ordering; same **generic** error for tag **failure** and **unknown** **`suite_id`** (`spec/CESS-v0.2.md` Sections 8.3, 8.5) |
