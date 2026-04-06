# CESS Algorithm Registry (living document)

**Version:** 0.2-draft  
**Last updated:** 2026-04-06  
**Maintainers:** CESS editorial board (repository maintainers)

This registry records **approved**, **excluded**, and **provisional** algorithms for cipher-agnostic CESS layers. The **normative** rules appear in `spec/CESS-v0.2.md` Section 3; this file is the **operational** checklist for pull requests.

## Admission criteria (all MUST hold)

1. **Two independent audits** from the qualifying auditor list in the specification (same paper team counts once for IACR work).  
2. **No NSA design input** for symmetric primitives; **no reliance on NIST/FIPS-only** review as the sole evidence.  
3. **No entry** on the **hard exclusion list** unless explicitly listed as “optional permitted” with rationale (currently **X25519** only; **Ed25519** is **normative** for inner-profile signatures per `spec/CESS-v0.2.md` Section 4.5).  
4. **Interop**: a **cipher suite identifier** can be allocated without collision (`spec/CESS-v0.2.md` Section 14.2 and **Cipher suite identifier assignment** below). Identifiers are **not** on-wire cleartext framing; see `spec/CESS-v0.2.md` Section 8.1 and 8.5.  
5. **Documentation**: audit citations with **version**, **date**, and **link** or stable identifier.  
6. **Test vectors**: at least one vector file updated in `vectors/` before “approved” status.  
7. **PQ-specific**: post-quantum algorithms MUST document **classical + PQ hybrid** behaviour with HKDF-BLAKE3 per `spec/CESS-v0.2.md` Section 7.

## Current approved algorithms

| Component | Algorithm | Audit evidence (examples) | Notes |
|-----------|-----------|-----------------------------|-------|
| Secret sharing | Shamir over GF(2^8), threshold k-of-n | Mathematical literature; see `spec/CRYPTO.md` | Fixed layer; not selectable |
| Password hash | Argon2id (RFC 9106) | PHC winner; Kudelski, Aumasson analyses | Fixed profile in spec |
| Integrity | BLAKE3 | NCC Group, Kudelski | Fixed layer (object and chunk integrity) |
| Integrity (standalone, inner profile) | BLAKE3 | NCC Group, Kudelski | Keyed **32-byte** tags between cascade layers or before signing; HKDF `info` per `spec/CESS-v0.2.md` Section 8.3; sample KATs in `vectors/blake3_integrity.toml` (see lookup table Notes) |
| Digital signature (inner profile) | Ed25519 | RFC 8032; Bernstein et al.; independent cryptanalysis | Normative when listed in lookup table (Section 4.5); long-term keys out of band; sample KATs in `vectors/ed25519_signing.toml` (`cess_runner` verification) |
| Classical KEM | BrainpoolP384r1 / BrainpoolP512r1 ECDH | RFC 5639; BSI TR-03111 | Point validation required |
| Outer session ECDH (Mode A) | **BrainpoolP384r1** ECDH **only** | RFC 5639; BSI TR-03111 | Mandatory for `K_outer` establishment; see `spec/CESS-v0.2.md` Section 6.1.1 |
| KDF | HKDF-BLAKE3 (RFC 5869 structure, HMAC-BLAKE3) | BLAKE3 paper; HKDF analysis | `info` strings in spec |
| AEAD (primary) | ChaCha20-Poly1305 (RFC 8439) | eSTREAM / extensive review | Primary bulk AEAD |
| AEAD (alt) | Serpent-256-CTR + Poly1305 | NESSIE Serpent; Poly1305 literature | Cascade-capable |
| AEAD (alt-2) | Twofish-256-CTR + Poly1305 | NESSIE; AES competition public analysis | `vectors/twofish.toml` KATs for allocated Twofish rows; `cess_runner::twofish_bulk` verification; cascade-capable; no NSA design input |
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
| X25519 | Bernstein design; extensive independent cryptanalysis; NIST later adoption does not negate prior audits; use where Brainpool ECDH is not selected for an additional handshake |

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

Each row is one **inner** cipher tuple per `spec/CESS-v0.2.md` Sections 4.2, 4.5, 6.1, 6.3, 6.6, and 7: **classical KEM**, **HKDF-BLAKE3**, **bulk AEAD or cascade**, optional **keyed BLAKE3 integrity** between layers (Section 6.3), optional **PQ KEM**, optional **Ed25519** signature over `suite_id` || `inner_blob` when the Signature column lists **Ed25519**. **KDF** is always **HKDF-BLAKE3** with suite-specific `info` as in Section 8.3. **Mode A** outer framing is fixed ChaCha20-Poly1305 (Section 6.6).

**Normative:** The meaning of each **`suite_id`** **MUST** be taken from the **lookup table** below. If an **informative** bit-field reading **conflicts** with a **lookup table** row, the **lookup table** is **authoritative** (`spec/CESS-v0.2.md` Section 8.5).

**Encoding structure (informative):** The **`suite_id`** value encodes inner profile components in a structured layout to aid implementation:

- **Bits 15–8:** **PQ KEM family** (for example **`0x00`**, **`0x01`**, **`0x02`**, **`0x03`**). **`0x00xx`** = classical only; **`0x01xx`** = FrodoKEM-1344 hybrid (except **`0x011x`**); **`0x011x`** = Classic McEliece 6688128 hybrid; **`0x012x`** = BrainpoolP512r1 + FrodoKEM-1344 hybrid; **`0x02xx`** = Ed25519-signed classical profiles (see table); **`0x03xx`** = reserved for Ed25519-signed PQ hybrid profiles (allocate via registry PR).  
- **Bits 7–4:** Classical inner KEM curve. **`0x_0_`** = BrainpoolP384r1; **`0x_1_`** = BrainpoolP512r1.  
- **Bits 3–0:** Bulk AEAD / cascade. **`0x__0`** = ChaCha20-Poly1305; **`0x__1`** = Serpent-256-CTR + Poly1305; **`0x__2`** = cascade ChaCha inner, Serpent outer; **`0x__3`** = Twofish-256-CTR + Poly1305 single layer; **`0x__4`** = cascade ChaCha inner, Twofish outer; **`0x__5`** = cascade Twofish inner, Serpent outer; **`0x__6`** = triple cascade ChaCha inner, Serpent middle, Twofish outer; **`0x__7`** = reserved.

**Informative:** The **`0x011x`** range **lies inside** **`0x01xx`**; **FrodoKEM-1344** applies to **`0x01xx`** **except** where **`0x011x`** is **McEliece**. **Reserved** **`0x0000`** and **`0x0001`** **preclude** a **pure** low-nibble **`0`** ChaCha encoding for the default **CESS-CORE** profile; **implementations MUST** still use the **lookup table** for **`0x0001`**.

### Classical inner profile combinatorics (informative)

For **classical-only** inner profiles (no PQ KEM), the **independent** policy dimensions below define a **Cartesian product** of **56** distinct combinations:

| Dimension | Values | Count |
|-----------|--------|------:|
| Classical inner KEM | BrainpoolP384r1; BrainpoolP512r1 | 2 |
| Bulk AEAD / cascade | ChaCha20-Poly1305; Serpent-256-CTR + Poly1305; Twofish-256-CTR + Poly1305; cascade ChaCha + Serpent; cascade ChaCha + Twofish; cascade Twofish + Serpent; triple ChaCha + Serpent + Twofish | 7 |
| Optional keyed BLAKE3 integrity (`spec/CESS-v0.2.md` Section 6.3) | absent; present | 2 |
| Optional Ed25519 signature (`spec/CESS-v0.2.md` Section 4.5) | absent; present | 2 |

**Product:** **2 × 7 × 2 × 2 = 56**.

**Currently allocated** in the **lookup table** below for **classical-only** inner profiles (PQ column **—**): **56** **`suite_id`** values covering the full **2 × 7 × 2 × 2** combinatorial product (**`0x0001`–`0x0007`**, **`0x0008`–`0x000f`**, **`0x0010`–`0x0030`**, **`0x0200`–`0x0207`**), plus reserved **`0x0000`**.

**`0x0000`** is a **reserved sentinel** and is **excluded** from the **56**-combination classical product; **56** assignable **`suite_id`** values are **allocated** for that product (**56 − 56 = 0** unallocated).

**Implementations MUST NOT** emit or accept **unlisted** codes for interoperable use; new assignments require a **registry PR** (rationale, vectors where required by admission criteria).

**Note:** The row **`0x0207`** is the **registered** profile that **combines** Twofish **single-layer** bulk, **optional** keyed BLAKE3 integrity **before** signing, and **Ed25519**; other cells of the **56** matrix are **not** implied by partial overlap with existing rows.

**Combinatorial coverage (informative):** Every **56**-cell classical combination has a **`suite_id`** row below. **`vectors/classical_suite_id_matrix.toml`** lists per-row **status**, vector file pointers, and **`pending_issue`** where KAT coverage is still incomplete. **Twofish** inner bulk for **`0x0004`–`0x0007`** and **`0x0203`–`0x0207`** is covered by **`vectors/twofish.toml`** (`cess_runner::twofish_bulk`). **Keyed BLAKE3 integrity** has sample KATs in **`vectors/blake3_integrity.toml`** (not yet one row per **`suite_id`** in **`0x0008`–`0x000f`**). **Ed25519** has sample KATs in **`vectors/ed25519_signing.toml`**. **BrainpoolP512r1** inner ECDH + HKDF sample material for **`0x0013`** is in **`vectors/ecdh_p512_inner.toml`** (Python **`scripts/verify_p512_ecdh_kat.py`** cross-checks ECDH). Rows without matching KAT entries remain **provisional** per admission criteria **6** until extended.

| `suite_id` | Classical inner KEM | PQ KEM | Bulk AEAD (inner) | Signature | Notes |
|------------|----------------------|--------|-------------------|-----------|-------|
| `0x0000` | — | — | — | — | **Reserved**; MUST reject (`spec/CESS-v0.2.md` Section 14.2). |
| `0x0001` | BrainpoolP384r1 | — | ChaCha20-Poly1305 | — | Default **CESS-CORE** inner profile; with **Mode A**, IKM matches outer ECDH (Section 6.1.1). |
| `0x0002` | BrainpoolP384r1 | — | Serpent-256-CTR + Poly1305 | — | Single-layer Serpent (Section 6.3). |
| `0x0003` | BrainpoolP384r1 | — | Cascade: ChaCha inner, Serpent outer | — | Default cascade (Section 4.4). |
| `0x0004` | BrainpoolP384r1 | — | Twofish-256-CTR + Poly1305 | — | Single-layer Twofish (Section 6.3); KAT `vectors/twofish.toml` (`suite_id` `0x0004`); `cess_runner::twofish_bulk`. |
| `0x0005` | BrainpoolP384r1 | — | Cascade: ChaCha inner, Twofish outer | — | KAT `vectors/twofish.toml` (`suite_id` `0x0005`); Section 4.4. |
| `0x0006` | BrainpoolP384r1 | — | Cascade: Twofish inner, Serpent outer | — | KAT `vectors/twofish.toml` (`suite_id` `0x0006`); Section 4.4. |
| `0x0007` | BrainpoolP384r1 | — | Triple cascade: ChaCha inner, Serpent middle, Twofish outer | — | KAT `vectors/twofish.toml` (`suite_id` `0x0007`); Section 13.8. |
| `0x0008` | BrainpoolP384r1 | — | ChaCha20-Poly1305 | — | Keyed BLAKE3 integrity (Section 6.3). Integrity KAT `vectors/blake3_integrity.toml` (`suite_id` `0x0008`). **Provisional** until full KAT coverage for this tuple. |
| `0x0009` | BrainpoolP384r1 | — | ChaCha20-Poly1305 | Ed25519 | Keyed BLAKE3 integrity; Ed25519 signing. **Provisional** until vectors (see `vectors/classical_suite_id_matrix.toml`). |
| `0x000a` | BrainpoolP384r1 | — | Serpent-256-CTR + Poly1305 | — | Keyed BLAKE3 integrity. Integrity KAT `vectors/blake3_integrity.toml` (`suite_id` `0x000a`). **Provisional** until full KAT coverage for this tuple. |
| `0x000b` | BrainpoolP384r1 | — | Serpent-256-CTR + Poly1305 | Ed25519 | Keyed BLAKE3 integrity; Ed25519 signing. **Provisional** until vectors (see `vectors/classical_suite_id_matrix.toml`). |
| `0x000c` | BrainpoolP384r1 | — | Cascade: ChaCha inner, Serpent outer | — | Keyed BLAKE3 integrity. **Provisional** until vectors (see `vectors/classical_suite_id_matrix.toml`). |
| `0x000d` | BrainpoolP384r1 | — | Cascade: ChaCha inner, Serpent outer | Ed25519 | Keyed BLAKE3 integrity; Ed25519 signing. **Provisional** until vectors (see `vectors/classical_suite_id_matrix.toml`). |
| `0x000e` | BrainpoolP384r1 | — | Twofish-256-CTR + Poly1305 | — | Keyed BLAKE3 integrity. Integrity KAT `vectors/blake3_integrity.toml` (`suite_id` `0x000e`). **Provisional** until full KAT coverage for this tuple. |
| `0x000f` | BrainpoolP384r1 | — | Cascade: ChaCha inner, Twofish outer | — | Keyed BLAKE3 integrity. **Provisional** until vectors (see `vectors/classical_suite_id_matrix.toml`). |
| `0x0010` | BrainpoolP512r1 | — | ChaCha20-Poly1305 | — | P512 inner KEM caveat (Section 6.1.1). |
| `0x0011` | BrainpoolP512r1 | — | Serpent-256-CTR + Poly1305 | — | Same IKM caveat as `0x0010`. |
| `0x0012` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Serpent outer | — | Same IKM caveat as `0x0010`. |
| `0x0013` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Twofish outer | Ed25519 | Keyed BLAKE3 integrity; Ed25519 signing. Sample P512 ECDH + HKDF material `vectors/ecdh_p512_inner.toml` (`suite_id` `0x0013`; `scripts/verify_p512_ecdh_kat.py`). **Provisional** until full inner KAT coverage for this tuple. |
| `0x0014` | BrainpoolP384r1 | — | Cascade: Twofish inner, Serpent outer | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x0015` | BrainpoolP384r1 | — | Cascade: Twofish inner, Serpent outer | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x0016` | BrainpoolP384r1 | — | Triple cascade: ChaCha inner, Serpent middle, Twofish outer | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x0017` | BrainpoolP384r1 | — | Triple cascade: ChaCha inner, Serpent middle, Twofish outer | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x0018` | BrainpoolP512r1 | — | ChaCha20-Poly1305 | Ed25519 | Signed variant of `0x0010` (Section 4.5). **Provisional** until vectors. |
| `0x0019` | BrainpoolP512r1 | — | ChaCha20-Poly1305 | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x001a` | BrainpoolP512r1 | — | ChaCha20-Poly1305 | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x001b` | BrainpoolP512r1 | — | Serpent-256-CTR + Poly1305 | Ed25519 | Signed variant of `0x0011`. **Provisional** until vectors. |
| `0x001c` | BrainpoolP512r1 | — | Serpent-256-CTR + Poly1305 | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x001d` | BrainpoolP512r1 | — | Serpent-256-CTR + Poly1305 | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x001e` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Serpent outer | Ed25519 | Signed variant of `0x0012`. **Provisional** until vectors. |
| `0x001f` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Serpent outer | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x0020` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Serpent outer | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x0021` | BrainpoolP512r1 | — | Twofish-256-CTR + Poly1305 | — | **Provisional**; P512 Twofish single-layer KATs not yet in `vectors/` (see `vectors/classical_suite_id_matrix.toml`). |
| `0x0022` | BrainpoolP512r1 | — | Twofish-256-CTR + Poly1305 | Ed25519 | **Provisional**; P512 Twofish + Ed25519 KATs pending (see `vectors/classical_suite_id_matrix.toml`). |
| `0x0023` | BrainpoolP512r1 | — | Twofish-256-CTR + Poly1305 | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x0024` | BrainpoolP512r1 | — | Twofish-256-CTR + Poly1305 | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x0025` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Twofish outer | — | **Provisional**; P512 ChaCha/Twofish cascade KATs pending (see `vectors/classical_suite_id_matrix.toml`). |
| `0x0026` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Twofish outer | Ed25519 | **Provisional**; P512 cascade + Ed25519 KATs pending (see `vectors/classical_suite_id_matrix.toml`). |
| `0x0027` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Twofish outer | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x0028` | BrainpoolP512r1 | — | Cascade: ChaCha inner, Twofish outer | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x0029` | BrainpoolP512r1 | — | Cascade: Twofish inner, Serpent outer | — | **Provisional**; P512 Twofish/Serpent cascade KATs pending (see `vectors/classical_suite_id_matrix.toml`). |
| `0x002a` | BrainpoolP512r1 | — | Cascade: Twofish inner, Serpent outer | Ed25519 | **Provisional**; P512 cascade + Ed25519 KATs pending (see `vectors/classical_suite_id_matrix.toml`). |
| `0x002b` | BrainpoolP512r1 | — | Cascade: Twofish inner, Serpent outer | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x002c` | BrainpoolP512r1 | — | Cascade: Twofish inner, Serpent outer | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x002d` | BrainpoolP512r1 | — | Triple cascade: ChaCha inner, Serpent middle, Twofish outer | — | **Provisional**; P512 triple-cascade KATs pending (see `vectors/classical_suite_id_matrix.toml`). |
| `0x002e` | BrainpoolP512r1 | — | Triple cascade: ChaCha inner, Serpent middle, Twofish outer | Ed25519 | **Provisional**; P512 triple cascade + Ed25519 KATs pending (see `vectors/classical_suite_id_matrix.toml`). |
| `0x002f` | BrainpoolP512r1 | — | Triple cascade: ChaCha inner, Serpent middle, Twofish outer | — | Keyed BLAKE3 integrity present. **Provisional** until vectors. |
| `0x0030` | BrainpoolP512r1 | — | Triple cascade: ChaCha inner, Serpent middle, Twofish outer | Ed25519 | Keyed BLAKE3 integrity present; Ed25519 signing. **Provisional** until vectors. |
| `0x0100` | BrainpoolP384r1 | FrodoKEM-1344 | ChaCha20-Poly1305 | — | **Provisional** PQ (Section 7.2). |
| `0x0101` | BrainpoolP384r1 | FrodoKEM-1344 | Serpent-256-CTR + Poly1305 | — | **Provisional** PQ. |
| `0x0102` | BrainpoolP384r1 | FrodoKEM-1344 | Cascade: ChaCha inner, Serpent outer | — | **Provisional** PQ. |
| `0x0110` | BrainpoolP384r1 | Classic McEliece 6688128 | ChaCha20-Poly1305 | — | **Provisional** PQ. |
| `0x0111` | BrainpoolP384r1 | Classic McEliece 6688128 | Serpent-256-CTR + Poly1305 | — | **Provisional** PQ. |
| `0x0112` | BrainpoolP384r1 | Classic McEliece 6688128 | Cascade: ChaCha inner, Serpent outer | — | **Provisional** PQ. |
| `0x0120` | BrainpoolP512r1 | FrodoKEM-1344 | ChaCha20-Poly1305 | — | **Provisional** PQ; P512 caveat. |
| `0x0121` | BrainpoolP512r1 | FrodoKEM-1344 | Serpent-256-CTR + Poly1305 | — | **Provisional** PQ. |
| `0x0122` | BrainpoolP512r1 | FrodoKEM-1344 | Cascade: ChaCha inner, Serpent outer | — | **Provisional** PQ. |
| `0x0200` | BrainpoolP384r1 | — | ChaCha20-Poly1305 | Ed25519 | Signed variant of `0x0001` (Section 4.5). Ed25519 KAT templates `vectors/ed25519_signing.toml`; `cess_runner` verification. |
| `0x0201` | BrainpoolP384r1 | — | Serpent-256-CTR + Poly1305 | Ed25519 | Signed variant of `0x0002`. Ed25519 KAT templates `vectors/ed25519_signing.toml`. |
| `0x0202` | BrainpoolP384r1 | — | Cascade: ChaCha inner, Serpent outer | Ed25519 | Signed variant of `0x0003`. Ed25519 KAT templates `vectors/ed25519_signing.toml`. |
| `0x0203` | BrainpoolP384r1 | — | Twofish-256-CTR + Poly1305 | Ed25519 | Signed variant of `0x0004`; inner bulk KAT `vectors/twofish.toml` (`suite_id` `0x0203`); Ed25519 KAT templates `vectors/ed25519_signing.toml`. |
| `0x0204` | BrainpoolP384r1 | — | Cascade: ChaCha inner, Twofish outer | Ed25519 | Signed variant of `0x0005`; inner bulk KAT `vectors/twofish.toml` (`suite_id` `0x0204`). |
| `0x0205` | BrainpoolP384r1 | — | Cascade: Twofish inner, Serpent outer | Ed25519 | Signed variant of `0x0006`; inner bulk KAT `vectors/twofish.toml` (`suite_id` `0x0205`). |
| `0x0206` | BrainpoolP384r1 | — | Triple cascade: ChaCha, Serpent, Twofish | Ed25519 | Signed variant of `0x0007`; inner bulk KAT `vectors/twofish.toml` (`suite_id` `0x0206`). |
| `0x0207` | BrainpoolP384r1 | — | Twofish single + optional keyed BLAKE3 integrity before sign | Ed25519 | Inner bulk KAT `vectors/twofish.toml` (`suite_id` `0x0207`; `blake3_integrity_key_hex`, `expected_blake3_integrity_tag_hex`). Ed25519 KAT templates `vectors/ed25519_signing.toml`. Section 6.3. |

**Unknown `suite_id` handling (normative):** Implementations MUST treat any **`suite_id`** value **not** listed in **this table** as **unsupported** and MUST **reject** the frame **without** attempting **inner** decryption, **unless** a **deployment-specific private-use agreement** documented **out-of-band** **explicitly authorises** the value. The **rejection** MUST **NOT** reveal which **`suite_id`** was received to any party **other** than a **local administrator log**, to avoid **oracle** attacks on the identifier space. **Outer** ChaCha20-Poly1305 tag **verification** **MUST** succeed **before** **`suite_id`** is **read** or **acted on**; **outer** tag **failure**, **Ed25519** **verification** **failure**, and **unknown** **`suite_id`** **rejection** **MUST** be **indistinguishable** to **remote** parties and **holders** (same **generic** error); **normative** ordering and leakage rules are in **`spec/CESS-v0.2.md`** Sections **4.5**, **8.3**, and **8.5**.

**Informative (registry maintenance):** **Unallocated** values include gaps not listed above (for example **`0x0031`–`0x00FF`** excluding listed rows, **`0x0103`–`0x010F`**, **`0x0113`–`0x011F`**, **`0x0123`–`0x01FF`**, **`0x0208`–`0x02FF`**, **`0x0300`–`0xFFFF`** until allocated).

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
| 2026-04-06 | **Twofish-256-CTR + Poly1305** (approved): `vectors/twofish.toml` KATs; optional standalone BLAKE3 integrity; **Ed25519** inner signing; **`suite_id`** `0x0004`–`0x0007` and `0x0203`–`0x0207`; runner `cess_runner::twofish_bulk` verification |
| 2026-04-06 | Lookup table Notes: KAT pointers for **`vectors/twofish.toml`**, **`vectors/blake3_integrity.toml`**, **`vectors/ed25519_signing.toml`**, **`vectors/ecdh_p512_inner.toml`**; **`vectors/classical_suite_id_matrix.toml`** per-row status; fix P512 Twofish row notes (P512 Twofish KATs not implied by P384 `twofish.toml` rows); **`0x0013`** KEM corrected to **BrainpoolP512r1** (matches `vectors/ecdh_p512_inner.toml`). |
| 2026-04-07 | Informative **56**-cell classical combinatorics (**`0x0000`** sentinel); allocate **38** **`suite_id`** rows (**`0x0008`–`0x000f`**, **`0x0013`–`0x0030`**); **`vectors/classical_suite_id_matrix.toml`**; classical **product** **closed** in lookup table |
