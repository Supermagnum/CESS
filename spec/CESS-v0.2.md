# CESS — Cryptologically Enchanted Shamir's Secret

**Version:** 0.2-draft  
**Last updated:** 2026-04-06 (see Document revision history)  
**Document type:** Normative specification  
**Keywords:** RFC 2119 (MUST, SHOULD, MAY)

---

## 1. Introduction

### 1.1 Motivation and scope

CESS defines a **layered** cryptographic system for **threshold secret sharing** with **authenticated encryption**, **password-based share wrapping**, optional **post-quantum hybrid key exchange**, and **hardware token** profiles. This document is intended as a **candidate** for publication as an **Informational RFC** and for **liaison** with **BSI** and **ANSSI** regarding European government adoption. It is also suitable for reference by procurement frameworks that require **independent algorithm review** outside NSA/NIST-only baselines.

The scope includes:

- Normative **data formats** for shares and encrypted payloads.  
- Normative **protocols** for enrollment and reconstruction.  
- Normative **primitive profiles** for the fixed layer and cipher-agnostic layer.  

Out of scope: specific product UI, national accreditation, or organisational key-governance policy beyond security-relevant technical requirements.

### 1.2 Relationship to existing standards

| Reference | Relationship |
|-----------|--------------|
| SLIP-0039 | Informative; CESS uses binary share envelopes and **off-wire** cipher negotiation (Section 4.6); suite identifiers are **not** cleartext framing (Section 8); mnemonic encoding is out of scope. |
| RFC 5639 | Normative for Brainpool curves. |
| BSI TR-03111 | Informative/normative practices for ECC key generation and validation alongside RFC 5639. |
| Feldman VSS (1987) | Informative; CESS does not mandate verifiable secret sharing in v0.2. |
| Pedersen VSS (1992) | Informative; future extension. |
| RFC 9106 | Normative for Argon2id parameters where cited. |
| RFC 8439 | Normative for ChaCha20-Poly1305. |
| IETF threshold cryptography | Informative; CESS aligns with threshold-sharing goals; see Section 2.4. |

**Note:** Normative references **exclude** NIST SP 800-series documents. Informative mentions of NIST material MAY appear with an explicit caveat that they are **not** used as sole audit evidence for CESS.

### 1.3 Terminology

- **Share:** A point `(x, y)` over GF(2^8) produced by Shamir’s scheme, plus envelope fields.  
- **Threshold k-of-n:** Any `k` distinct shares sufficient to reconstruct the secret polynomial’s constant term.  
- **Fixed layer:** Shamir GF(2^8), Argon2id profile, BLAKE3 integrity, Reed–Solomon profile.  
- **Cipher-agnostic layer:** KEM, KDF, bulk AEAD or cascade, optional keyed BLAKE3 integrity between cascade layers, optional PQ KEM, optional Ed25519 inner-profile signature, selected from the Algorithm Registry.  
- **Holder anonymity:** Share holders do not learn global parameters `k`, `n`, or their index in the quorum without side channels (see Section 5.1).  
- **CESS-PQ:** Optional hybrid classical+PQ KEM combining into HKDF-BLAKE3.  
- **Outer envelope:** A **profile-independent** authenticated encryption layer (Section 8) that conceals the cipher suite identifier and inner ciphertext from observers without `K_outer`; **Mode A** derives `K_outer` from **BrainpoolP384r1** ECDH (Section 6.1.1).  
- **Profile pre-negotiation:** Agreement on the full cipher tuple **before** any ciphertext is emitted, so **no** in-band suite identifier is transmitted (Section 8).

### 1.4 Document conventions

- **RFC 2119** keywords apply.  
- Integers are **big-endian** unless stated otherwise.  
- Hexadecimal is **lowercase** in test vectors.

---

## 2. Security Model

### 2.1 Threat model

CESS assumes defenders can enforce **air-gapped enrollment** for root secrets, use **hardware security modules** or smartcards where required, and operate over a **decades-long** horizon. Attackers may compromise any subset of fewer than `k` shares, and may attempt **coercion** against holders.

### 2.2 Attacker model

- **SSS layer:** Information-theoretic security for the secret **given** uniformly random coefficients and independent `x` values (see Appendix A and `spec/CRYPTO.md`).  
- **Encryption layer:** Computational security against adversaries bounded by standard assumptions for selected primitives.

### 2.3 Non-goals

CESS does **not** provide:

- **Active** protection against collusion of `k` or more share holders.  
- **On-line** revocation of shares without additional infrastructure.  
- **Legal** validity of escrow arrangements (jurisdiction-specific).

### 2.4 Government usage considerations

CESS is **suitable** for technical architectures supporting:

- **Multi-party key escrow** across jurisdictions (technical split; legal review separate).  
- **Holder anonymity** when envelope design conceals metadata (Section 8.6).  
- **Coercion resistance** when shares are distributed and procedures limit single points of coercion.  
- **Air-gapped enrollment** as a normative baseline (Section 9).  
- **Long-term** confidentiality when algorithms and key lengths match agency policy.  
- **Hardware token binding** via the CCID/smartcard profile (Section 11).

Informative liaison: **BSI**, **ANSSI**, **ENISA**, **NATO/NCSA**, and **IETF** threshold cryptography work.

---

## 3. Audit Requirement

### 3.1 Independent audit (definition)

An **independent audit** for CESS is a publicly documented cryptographic evaluation by a team **financially and organisationally separate** from the algorithm’s designers, which reports strengths and weaknesses against published cryptanalytic goals.

### 3.2 Qualifying auditor list

At least **two** evaluations from distinct sources drawn from:

- NESSIE; CRYPTREC; ECRYPT / eSTREAM; IACR peer-reviewed cryptanalysis (one per paper team); BSI; NCC Group; Cure53; Kudelski Security; JP Aumasson (personal audits); PHC committee.

### 3.3 Disqualifying conditions

Algorithms with **NSA design input** (symmetric primitives), or relying **only** on NSA/NIST/FIPS processes without independent review, do **not** satisfy the audit requirement.

### 3.4 Algorithm exclusion list

The following are **prohibited** in conforming implementations:

| Algorithm | Rationale |
|-----------|-----------|
| AES (any mode) | NSA-designed S-box |
| SHA-2 | NSA-designed |
| SHA-3 / Keccak | NSA competition involvement |
| P-256, P-384, P-521 | NIST/NSA curves |
| ML-KEM / Kyber | NIST PQC process exclusion |
| Dual_EC_DRBG | Confirmed backdoor |
| RC4, DES, 3DES | Broken or NSA-tainted |
| HMAC-SHA-* | Inherits SHA-2 exclusion |

### 3.5 Optional permitted algorithms

**X25519** MAY be used only where deployment documentation states: independent audits predate or exceed reliance on later NIST standardisation; curve design is attributed to **Bernstein** et al., not NSA. **Ed25519** is **not** optional here; it is a **normative** inner-profile signature primitive (Section 4.5).

---

## 4. Cipher-Agnostic Architecture

### 4.1 Layer model

1. **Fixed layer (mandatory):** GF(2^8) Shamir; Argon2id; BLAKE3; Reed–Solomon profile.  
2. **Cipher-agnostic layer (selectable):** Brainpool ECDH; HKDF-BLAKE3; bulk AEAD or cascade; optional keyed BLAKE3 integrity between cascade layers; optional PQ KEM + hybrid combiner; optional Ed25519 inner-profile signature (Section 4.5).

### 4.2 Cipher tuple

A **cipher tuple** is an ordered selection:

`(classical_kem, kdf, bulk_aead_or_cascade [, pq_kem] [, optional_blake3_integrity] [, optional_signature])`

- **`optional_signature`:** **Ed25519** over **`suite_id` || `inner_blob`** when registered (Section 4.5). **Omit** when the profile has no signing step.  
- **`optional_blake3_integrity`:** **Keyed** **BLAKE3** **32-byte** tags between cascade layers or over the full cascade output before signing, when registered (Section 6.3).

### 4.3 Compliant examples (informative)

- ChaCha20-Poly1305 alone.  
- Serpent-256-CTR + Poly1305 alone; Twofish-256-CTR + Poly1305 alone.  
- ChaCha inner, Serpent+Poly1305 outer (default cascade).  
- Registered non-default cascade orders (distinct **`suite_id`** each; Section 4.4).  
- Brainpool ECDH + HKDF-BLAKE3 + tuple above, optional keyed BLAKE3 integrity, optional Ed25519 signing.  
- Optional: FrodoKEM-1344 + classical + HKDF-BLAKE3 hybrid.

### 4.4 Cascade rules

When cascading AEADs, implementations MUST define **order** (inner vs outer). CESS default: **inner = ChaCha20-Poly1305**, **outer = Serpent-256-CTR + Poly1305** on the inner ciphertext (**`suite_id`** **`0x0003`**). Both layers MUST use **distinct keys** derived per Section 6.

**Normative:** Any cascade order other than the default ChaCha inner / Serpent outer MUST have its own row in `ALGORITHM-REGISTRY.md` (Cipher suite identifier lookup table), with test vectors as required by admission criteria. Triple cascades follow the same rule: each unique ordering is a distinct `suite_id`. Implementations MUST NOT infer cascade order from any field other than the registered `suite_id` and deployment documentation for that row.

### 4.5 Inner profile signatures (normative)

When `optional_signature` is Ed25519 (Section 4.2), signing is encrypt-then-sign with respect to inner AEAD and cascade layers: the signature is computed after all inner confidentiality and AEAD steps (including optional keyed BLAKE3 integrity steps in Section 6.3) on the octets that form `inner_blob` before the signature field is inserted into Mode A outer plaintext.

**Ed25519 signed message:** Verification is over `suite_id` || `inner_blob` (big-endian `suite_id`; `inner_blob` is the inner ciphertext octets only; the 64-byte signature is not included in the signed string).

**Mode A outer plaintext** when the lookup table lists Ed25519 for that `suite_id`: `suite_id` (2 bytes) || `ed25519_signature` (64 bytes) || `inner_blob` (variable). Unsigned profiles remain `suite_id` || `inner_blob` only (Section 6.6).

**Normative:** Ed25519 verification MUST complete successfully before any inner AEAD decryption or cascade unpacking; on failure, implementations MUST reject the frame with the same generic externally observable error as outer Poly1305 failure and unknown `suite_id` (Section 8.3). Rejection MUST NOT reveal the received `suite_id` to remote parties or holders beyond what successful outer decryption already exposes through authenticated outer plaintext; local administrator logs MAY record distinct failure causes.

**Signing keys:** Long-term Ed25519 private keys are not derived from the Mode A ephemeral BrainpoolP384r1 ECDH; they MUST be managed outside that session (for example GnuPG web of trust, Galdralag long-term keys, or equivalent deployment policy).

**Normative:** The Ed25519 signing private key MUST NOT be the same key as any private key used for ECDH or KEM key agreement in the same session (including Brainpool, optional X25519, or PQ hybrid components).

### 4.6 Cipher negotiation

Implementations MUST advertise supported tuples as a **list of cipher suite identifiers** (Section 8.5, `ALGORITHM-REGISTRY.md`) during **secure pre-transport** negotiation (authenticated session establishment, enrollment ceremony, or other **out-of-band** agreement). Peers MUST select the **highest mutually preferred** suite or abort.

Implementations MUST **not** encode negotiated suite choice as **cleartext** framing on the wire (Section 8.1).

### 4.7 Upgrade path

**Version** values for the share envelope **MUST** be carried **inside** authenticated **inner** plaintext (after inner decryption; Section 8.3), not in the outer AEAD plaintext. They govern format evolution. Implementations MUST reject unknown major versions after successful **inner** decryption and authentication.

---

## 5. Fixed Layer Specification

### 5.1 Shamir’s Secret Sharing over GF(2^8)

**Field:** GF(2^8) with reduction polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B), identical to the AES field.

**Polynomial:** For threshold `k`, coefficients `a_0 .. a_{k-1}` with `a_0` = secret byte; random `a_1..a_{k-1}` uniformly in GF(2^8) for enrollment randomness.

**Shares:** For `i = 1 .. n`, `x_i = i` (as field element); `y_i = f(x_i)`. Implementations MUST use **non-zero** `x` values.

**Reconstruction:** Lagrange interpolation at `x=0` (see test vectors).

**Share format:** See Section 8 (envelope).

**Holder anonymity:** Implementations SHOULD NOT embed `k`, `n`, or human-readable indices in plaintext metadata. Duplicate detection MUST use **constant-time** or **oblivious** comparisons where feasible (Section 8.7).

### 5.2 Reed–Solomon erasure coding profile

Data shards (as opposed to key shards) use RS over the same GF(2^8) with parameters in test vectors `vectors/reed_solomon.toml`. Implementations MUST verify shard integrity with BLAKE3 before decode.

### 5.3 BLAKE3 integrity

BLAKE3 **MUST** be used for chunk and object integrity as specified in envelope and protocol sections. Keyed modes MUST use 32-byte keys unless otherwise specified.

### 5.4 Argon2id password hashing profile

| Parameter | Value |
|-----------|-------|
| Memory | 65536 KiB |
| Iterations | 3 |
| Parallelism | 4 |
| Salt length | 16 bytes (random) |
| Output length | 32 bytes |

PIN minimum length and rejection behaviour align with `vectors/argon2id.toml`.

---

## 6. Cipher-Agnostic Layer Specification

### 6.1 Classical KEM (Brainpool)

Implementations MUST support **BrainpoolP384r1** and **BrainpoolP512r1** ECDH per RFC 5639 for **cipher-agnostic** inner KEM and related profiles.

**Key generation:** Private scalars MUST be uniformly random in `[1, n-1]`.

**ECDH:** Shared secret is the **x-coordinate** of the shared point, **32-byte** or **48-byte** fixed-length encoding per implementation profile — implementations MUST document encoding and use it consistently with test vectors.

**Point validation:** Incoming public points MUST be validated; **invalid curve points MUST be rejected** (including point at infinity, wrong curve, wrong order).

#### 6.1.1 Outer session ECDH (Mode A)

For **Mode A — fixed outer wrapper** (Section 8.2), **session key establishment** for the **profile-independent** outer layer **MUST** use **ephemeral** ECDH on **BrainpoolP384r1** **only**: each party **MUST** generate **fresh** ephemeral key pairs for the **outer** handshake unless a **deployment profile** documents an explicit exception (for example hardware-bound long-term keys). Implementations MUST **not** use **BrainpoolP512r1** or any other curve for the ECDH that produces `classical_shared_secret` feeding `K_outer` (Section 6.6).

**Normative:** The **shared secret** is the **x-coordinate** of the ECDH result, **48-byte** fixed-length encoding (big-endian) consistent with `vectors/ecdh_brainpool.toml` and RFC 5639.

**Informative rationale:** **BrainpoolP384r1** is already an **approved** classical KEM curve in `ALGORITHM-REGISTRY.md`; it is **BSI**-aligned (RFC 5639, BSI TR-03111) with **no** NSA curve design input; it targets roughly **192-bit** classical security (**stronger** than P-256-class curves, **lighter** than BrainpoolP512r1); it matches the registry’s existing emphasis on **P384/P512** over P-256-class curves; mandating it for the **outer** anchor reuses **only** registry-approved primitives and gives a **single** well-audited curve for **all** CESS **Mode A** outer sessions.

**Informative:** In **Mode A**, **inner** HKDF chains that use the **same** classical IKM as `K_outer` therefore derive from **BrainpoolP384r1** ECDH only. Deployments that **require** **BrainpoolP512r1** ECDH for **inner** keys **without** sharing that IKM with the outer layer **MUST** use an **additional** ECDH or **Mode B** framing as documented in their profile (not further specified in v0.2).

### 6.2 KDF profile (HKDF-BLAKE3)

HKDF **MUST** follow RFC 5869 using **HMAC-BLAKE3** as the PRF.

- **Salt:** Zero-length salt is represented as `32` zero bytes for extraction input processing per implementation profile in `vectors/hkdf_blake3.toml`.  
- **IKM:** Classical shared secret, or `classical_shared || pq_shared` for hybrid.  
- **Info:** UTF-8 strings `cess-kem-v1` (KEM) and `cess-pin-v1` (PIN wrap).  
- **Output length:** **32 bytes** for session keys unless a profile requires 64 bytes (see vectors).

### 6.3 Bulk AEAD profiles

**ChaCha20-Poly1305:** RFC 8439; 12-byte nonce; 32-byte key.

**Serpent-256-CTR + Poly1305:** Serpent uses **32-byte** key, **16-byte** CTR block; Poly1305 uses **32-byte** one-time key and **RFC 8439** MAC data layout over `AAD || ciphertext` with padding as in `vectors/bulk_aead.toml`.

**Twofish-256-CTR + Poly1305:** Twofish uses **256-bit** key, **128-bit** block, **16** rounds; **CTR** mode; Poly1305 uses **32-byte** one-time key and the same RFC 8439 MAC data layout over `AAD || ciphertext` with padding as in `vectors/bulk_aead.toml` (MAC construction). **Known-answer** ciphertexts for Twofish and Twofish cascades are in **`vectors/twofish.toml`** (`schema` `cess-twofish-v0.2`).

**Cascade:** Inner ChaCha20-Poly1305 on plaintext; outer Serpent-CTR then Poly1305 on inner ciphertext; **distinct** subkeys. Non-default cascade orders (including Twofish and triple cascades) are **normative** only where listed in `ALGORITHM-REGISTRY.md` (Section 4.4).

**Optional keyed BLAKE3 integrity (between cascade layers or before signing):** When a registered profile includes this step, the **key** is **32** bytes from **HKDF-BLAKE3** with **IKM** from session material per Section 6.2 and **distinct** `info` per Section 8.3. The **tag** is **32** bytes (**BLAKE3** output). **Position:** compute keyed BLAKE3 over the innermost AEAD ciphertext before the next cascade layer, or over the full cascade output before Ed25519 signing when no further AEAD layer follows. Profiles without this step omit it entirely.

### 6.4 PIN-derived key wrapping

1. Argon2id output (32 bytes) as IKM.  
2. HKDF-BLAKE3 with `info = "cess-pin-v1"` → 32-byte wrap key.  
3. AEAD encrypt share material (ChaCha20-Poly1305, Serpent profile, or Twofish profile per Section 6.3 when registered).

### 6.5 Session key material

Session keys MUST be **32 bytes** unless a profile explicitly uses 64-byte expanded keys. **Sensitive intermediates MUST be zeroised** (Section 13.3).

### 6.6 Normative outer wrapper construction (Mode A)

When **Mode A — fixed outer wrapper** (Section 8.2) is used, the **outer** layer **MUST** be built **exactly** from the following **registry-approved** components (no additional algorithms):

1. **Outer key agreement:** **Ephemeral** **BrainpoolP384r1** ECDH per Section 6.1.1, producing `classical_shared_secret`.  
2. **Outer KDF:** **HKDF-BLAKE3** per Section 6.2: **IKM** = `classical_shared_secret`, **or** `classical_shared_secret || pq_shared_secret` when CESS-PQ applies (classical part **always** from step 1, concatenation order per Section 7.2); **salt** as in Section 6.2; **info** = UTF-8 `cess-outer-envelope-v1`; **output length** **32 bytes** → **`K_outer`**.  
3. **Outer AEAD:** **ChaCha20-Poly1305** per Section 6.3 and RFC 8439; **key** = `K_outer`; **12-byte** nonce; **AAD** empty unless a **registered** deployment profile defines non-empty AAD.  
4. **Outer AEAD plaintext:** Exactly one of the following (no additional octets before encryption):
   - **Unsigned profiles:** `suite_id` (big-endian, 2 bytes) || `inner_blob`, where `inner_blob` is the inner ciphertext (variable length) produced by the selected inner profile.  
   - **Ed25519 profiles** (see `ALGORITHM-REGISTRY.md`, Section 4.5): `suite_id` || `ed25519_signature` (64 bytes) || `inner_blob`.  

Outer plaintext MUST NOT include the envelope version byte; envelope version MUST be carried inside inner plaintext after inner decryption (Section 8.3).

**Informative:** This construction uses only registry-approved primitives (including optional Ed25519 signing when listed); it keeps the outer wrapper auditable.

`K_outer` MUST be used **only** for this **outer** ChaCha20-Poly1305 layer. **Inner** keys for the selected suite MUST be derived with **distinct** HKDF-BLAKE3 `info` strings that **include** the suite identifier **only after** authenticated outer decryption (Section 8.3) or from pre-negotiation state (Mode B / Section 8.2.1).

---

## 7. CESS-PQ Extension

### 7.1 PQ KEM profiles

**Primary:** FrodoKEM-1344. **Alternative:** Classic McEliece 6688128. **ML-KEM is excluded.**

### 7.2 Hybrid combiner

```
session_key = HKDF-BLAKE3(
  ikm = classical_shared_secret || pq_shared_secret,
  salt = <as in HKDF profile>,
  info = "cess-kem-v1"
)
```

When **Mode A** applies, `classical_shared_secret` **MUST** be the **BrainpoolP384r1** ECDH output (Section 6.1.1).

### 7.3 Feature gating

PQ features MUST be **off by default** until explicitly enabled; UI and logs MUST warn about **size and performance** impact.

### 7.4 Audit tracking

Deployments SHOULD record PQ algorithm versions and audit report identifiers in configuration management.

---

## 8. Share Format

### 8.1 Cleartext leakage prohibition

Implementations MUST **not** transmit the **cipher suite identifier**, **profile metadata**, **algorithm discriminators**, or **any field** that reveals which symmetric cipher (including cascade order), which classical ECDH curve, whether a PQ hybrid was used, which KDF labelling was applied, or which authentication or MAC construction was used, **outside** an **authenticated encryption boundary** established with **session key material** known only to authorised parties.

**Normative:** Implementations **MUST NOT** transmit the **cipher suite identifier**, **profile metadata**, or **any algorithm discriminator** in **cleartext** **outside** the **authenticated encryption boundary** (outer ChaCha20-Poly1305 in **Mode A**, or the **inner** AEAD in **Mode B** / Section 8.2.1). **Ephemeral** ECDH **public** keys for **Mode A** remain visible on the wire per Section 6.1.1.

**Normative:** An **interceptor** who does **not** possess the keys required to decrypt and verify the **outermost** CESS framing layer used for a given transmission MUST **not** be able to determine the **inner** cipher profile from any octet of that transmission, **except** for **length**, the **Mode A** **outer** nonce (Section 8.3), and other unavoidable **physical-layer** observables.

**Informative:** A **fixed** normative **outer** AEAD (Section 8.3) is **public** by design; the **wildcard** property applies to **inner** profiles. The cleartext **outer** nonce does **not** encode **suite_id** or inner algorithm choice. For **Mode A**, ECDH **public keys** on the wire are **always** for **BrainpoolP384r1** (Section 6.1.1); observers learn **that** outer establishment curve **only**, **not** the **inner** cipher profile. **Mode B** or **additional** ECDH handshakes may use other **approved** curves per Section 6.1.

### 8.2 Bootstrapping (normative)

Exactly **one** of the following approaches MUST apply to a given share or session:

**Mode A — Fixed outer wrapper (in-band suite after decryption):** Parties perform **ephemeral** **BrainpoolP384r1** ECDH per Section 6.1.1, then build the **outer** wrapper per Section 6.6 (and optional PQ hybrid in the **outer** KDF IKM). The **wire** carries **only** the **outer** AEAD output (Section 8.3). **Plaintext** of the outer AEAD is **`suite_id` || `inner_blob`**, or **`suite_id` || `ed25519_signature` || `inner_blob`** when the profile includes Ed25519 (Sections 4.5 and 6.6). **Interceptors** without `K_outer` learn **nothing** about `suite_id` or inner algorithms.

**Mode B — Profile pre-negotiation (no in-band identifier):** The full cipher tuple (or equivalent profile reference) is agreed **out-of-band** (enrollment, ceremony, pre-configured policy) or over a **separate** authenticated channel **before** the ciphertext frame is emitted. Implementations MUST **not** place `suite_id` or **any** algorithm discriminator in the transmitted frame. The wire carries **only** ciphertext produced under the **pre-agreed** profile (and optional minimal framing agreed in that same pre-negotiation).

**PIN-only** or **offline** share storage without ECDH MUST use **Mode B** (suite fixed at enrollment) unless a **separate** key-establishment step supplies `K_outer` for **Mode A**.

#### 8.2.1 Out-of-band session key and cipher profile

When **session key material** and the **full cipher profile** are established **entirely out-of-band** (informative examples: **GR-K-GDSS** and **Galdralag** ephemeral ECDH flows, as defined by those deployments), the **in-band** **16-bit** suite identifier is **optional** and need not be transmitted. Implementations **MAY** use **Mode B** (or equivalent **inner-only** framing) with **no** `suite_id` on the wire.

**Normative:** If **any** `suite_id` or profile metadata is transmitted **in-band**, it **MUST** be protected by the **Mode A** outer wrapper (Section 6.6): ephemeral BrainpoolP384r1 ECDH, HKDF-BLAKE3 to `K_outer`, ChaCha20-Poly1305, with outer plaintext as defined in Section 8.3 (`suite_id` || `inner_blob`, or `suite_id` || `ed25519_signature` || `inner_blob` when Ed25519 applies). **Implementations MUST NOT** expose a cleartext suite identifier outside that authenticated boundary (Section 8.1).

### 8.3 Mode A: outer ciphertext (normative)

The **outer** layer MUST be **ChaCha20-Poly1305** (RFC 8439): **32-byte** key `K_outer`, **12-byte** nonce, ciphertext and **16-byte** tag per the RFC data model.

**Normative (processing order):** **Outer** ChaCha20-Poly1305 **authentication** (Poly1305 tag verification) **MUST** complete **successfully** **before** **`suite_id`** is **read** or **acted on**; if tag verification **fails**, implementations MUST **reject** the frame **without** examining **`suite_id`**, using the **same** **generic** externally observable **error** as for **unknown** **`suite_id`** (Section 8.5). **Only** after **successful** outer authentication **may** implementations parse **`suite_id`** and apply **inner** processing rules.

**Normative:** If, **after** successful outer authentication, **`suite_id`** is **`0x0000`**, implementations MUST **reject** the envelope (`suite_id` is reserved; Section 14.2).

**Normative:** If **`suite_id`** is **not** listed in **`ALGORITHM-REGISTRY.md`** (**Cipher suite identifier lookup table**), **unless** a **deployment-specific private-use agreement** documented **out-of-band** **explicitly authorises** the value, implementations MUST **reject** the frame **without** attempting **inner** decryption. **Rejection** and **leakage** rules are in **Section 8.5**.

**Normative (Ed25519):** If the lookup table lists **Ed25519** for the parsed **`suite_id`**, implementations MUST treat the next **64** octets as **`ed25519_signature`** and the remainder as **`inner_blob`**, MUST verify **Ed25519** over **`suite_id` || `inner_blob`** before any inner AEAD decryption, and MUST reject with the same generic externally observable error as outer tag failure and unknown **`suite_id`** on verification failure (Section 4.5). If the lookup table does **not** list Ed25519 for **`suite_id`**, **`inner_blob`** begins immediately after **`suite_id`**.

**On the wire:**

| Field | Size | Description |
|-------|------|-------------|
| `outer_nonce` | 12 bytes | Nonce; implementations MUST ensure **nonce uniqueness** per `K_outer` (random or deterministic counter per deployment policy). |
| `outer_ciphertext` | variable | Ciphertext concatenated with Poly1305 tag (RFC 8439). |

**Outer plaintext** (input to ChaCha20-Poly1305 encryption, **AAD** empty unless a deployment profile sets registered AAD) **MUST** be **exactly**:

| Field | Size | Description |
|-------|------|-------------|
| `suite_id` | 2 bytes | Big-endian **16-bit** cipher suite identifier (`ALGORITHM-REGISTRY.md`) |
| `ed25519_signature` | 0 or 64 bytes | **Present** only when the lookup table lists **Ed25519** for this **`suite_id`** (Section 4.5). |
| `inner_blob` | variable | **Inner** ciphertext from the **selected** inner profile (AEAD tuple, cascade, optional keyed BLAKE3 integrity, as specified for that suite). **Envelope** **version** (Section 4.7) **MUST** appear **inside** the **plaintext** **protected** **by** **the** **inner** **layer** **after** **inner** **decryption** (e.g. first byte of inner plaintext per inner suite), **not** in **outer** plaintext.

**Inner** keys MUST be derived from the same ECDH (and optional PQ) IKM as `K_outer` using **distinct** HKDF-BLAKE3 `info` values that **uniquely** identify the negotiated suite (e.g. UTF-8 `cess-inner-` concatenated with the **16-bit** `suite_id` encoded in **big-endian** hex). Implementations MUST **not** derive inner keys until `suite_id` is obtained from **authenticated** outer plaintext or from **Mode B** / **Section 8.2.1** pre-negotiation state.

**HKDF-BLAKE3 `info` for optional keyed BLAKE3 integrity keys (normative):** Use UTF-8 `cess-blake3-integrity-` concatenated with the **16-bit** `suite_id` in **lowercase** **hexadecimal** (4 characters), for example `cess-blake3-integrity-0004` for `suite_id` **0x0004**. Implementations MUST NOT reuse these keys for AEAD bulk encryption.

Implementations MAY encrypt Shamir coordinate `x` and metadata inside `inner_blob` to support holder anonymity.

### 8.4 Mode B: pre-negotiated inner only (normative)

The transmitted object is **only** `inner_blob`: authenticated encryption under the **pre-agreed** profile. **No** `suite_id` field appears on the wire. **Version** and share fields reside **inside** the inner plaintext or authenticated data as defined in the deployment profile. **Inner** keys MUST be derived per the **pre-agreed** profile: when IKM comes from ECDH, use the **same** HKDF-BLAKE3 `info` pattern as Section 8.3 with `suite_id` from **configuration**; when IKM comes from PIN wrap or enrollment-only material, use Section 6.4 or a **documented** profile that **never** places `suite_id` in cleartext. Fully **out-of-band** key and profile agreement (Section 8.2.1) **MAY** omit **both** **Mode A** **outer** **wrapper** **and** **in-band** **`suite_id`** when **no** **identifier** **is** **sent** **in-band**.

### 8.5 Cipher suite identifier registry

The **16-bit** suite identifier space is defined in **Section 14.2**. **`ALGORITHM-REGISTRY.md`** holds the **canonical** numeric **`suite_id`** assignments (**Cipher suite identifier lookup table**) and the PR workflow under **Cipher suite identifier assignment**. Suite IDs are an **internal** mapping for implementations, documentation, and **plaintext** use **inside** Mode A outer decryption or **off-wire** negotiation. They are **not** a cleartext **framing** field visible to third parties.

**Normative:** The meaning of each **`suite_id`** **MUST** be taken from the **Cipher suite identifier lookup table** in **`ALGORITHM-REGISTRY.md`**. If an **informative** bit-field reading (below) **conflicts** with a **lookup table** row, the **lookup table** is **authoritative**.

**Encoding structure (informative):** The **`suite_id`** value encodes inner profile components in a structured layout to aid implementation:

- **Bits 15–8:** **PQ KEM family** (for example **`0x00`** vs **`0x01`** vs **`0x02`**). **`0x00xx`** = classical only; **`0x01xx`** = FrodoKEM-1344 hybrid (except **`0x011x`**); **`0x011x`** = Classic McEliece 6688128 hybrid; **`0x012x`** = BrainpoolP512r1 + FrodoKEM-1344 hybrid; **`0x02xx`** = Ed25519-signed variants of classical **`0x00xx`**-family profiles (see lookup table); **`0x03xx`** = reserved for Ed25519-signed PQ hybrid variants (allocate via registry PR).  
- **Bits 7–4:** Classical inner KEM curve. **`0x_0_`** = BrainpoolP384r1; **`0x_1_`** = BrainpoolP512r1.  
- **Bits 3–0:** Bulk AEAD / cascade selection. **`0x__0`** = ChaCha20-Poly1305; **`0x__1`** = Serpent-256-CTR + Poly1305; **`0x__2`** = cascade (ChaCha inner, Serpent outer); **`0x__3`** = Twofish-256-CTR + Poly1305 single layer; **`0x__4`** = cascade (ChaCha inner, Twofish outer); **`0x__5`** = cascade (Twofish inner, Serpent outer); **`0x__6`** = triple cascade (ChaCha inner, Serpent middle, Twofish outer); **`0x__7`** = reserved for future allocation.

**Informative:** The **`0x011x`** range **lies inside** the **`0x01xx`** span; **FrodoKEM-1344** applies to **`0x01xx`** **except** where **`0x011x`** denotes **Classic McEliece 6688128** per the lookup table. **Reserved** **`0x0000`** and the **lookup table** row for **`0x0001`** (BrainpoolP384r1 + ChaCha20-Poly1305) **preclude** a **pure** low-nibble **`0`** ChaCha code for that default **CESS-CORE** profile; **implementations MUST** still use the **lookup table** for **`0x0001`**.

**Unknown `suite_id` handling (normative):** Implementations MUST treat any **`suite_id`** value **not** listed in **`ALGORITHM-REGISTRY.md`** (**Cipher suite identifier lookup table**) as **unsupported** and MUST **reject** the frame **without** attempting **inner** decryption, **unless** a **deployment-specific private-use agreement** documented **out-of-band** **explicitly authorises** the value. The **rejection** MUST **NOT** reveal which **`suite_id`** was received to any party **other** than a **local administrator log**, to avoid **oracle** attacks on the identifier space. **Outer** tag **verification failure** (Section 8.3), **Ed25519** **verification** **failure** **(Section** **8.3)**, and **unknown** **`suite_id`** **rejection** **MUST** be **indistinguishable** to **remote** parties and **holders** (same **generic** error); **only** **local administrator** logs **may** record **different** causes.

### 8.6 Metadata concealment

Plaintext metadata that reveals `k`, `n`, or index SHOULD NOT be transmitted unencrypted **inside** layers where policy requires concealment from holders.

### 8.7 Duplicate share detection

Implementations MUST detect duplicate shares without leaking index through error messages (constant-time compare of cryptographic digests).

---

## 9. Enrollment Protocol

### 9.1 Air-gap requirement

**Normative:** Root secret generation and initial splitting **SHOULD** occur on an **air-gapped** system with audited software supply chain.

### 9.2 Entropy

CSPRNG seed **MUST** meet platform requirements (hardware RNG where available).

### 9.3 Session key generation

Session keys **MUST** be derived per Section 6.2 after authenticated ECDH (and optional PQ). When **Mode A** applies, ECDH **MUST** follow Section 6.1.1 and `K_outer` **MUST** be derived per Section 6.6 before encrypting the outer envelope.

### 9.4 Encryption sequence

Encrypt source material with the selected **inner** AEAD profile; verify integrity tags before splitting. Apply **Mode A** or **Mode B** framing per Section 8.2: **never** emit `suite_id` or profile discriminators in cleartext.

### 9.5 SSS split

Produce `n` shares with threshold `k`.

### 9.6 Per-share PIN enrollment

Derive wrap keys per Section 6.4; never store PINs in plaintext.

### 9.7 Post-enrollment verification

**Mandatory dry-run:** Reconstruct on a **non-production** quorum at least once using test data.

### 9.8 Source destruction

After successful verification, source plaintext **SHOULD** be securely erased (implementation-defined).

---

## 10. Reconstruction Protocol

Collect at least `k` shares; authenticate holders (PIN, optional biometric per deployment); detect duplicates; reconstruct polynomial; decrypt **outer** then **inner** layers when **Mode A** applies (Section 8); verify BLAKE3 and AEAD tags; zeroise intermediates.

---

## 11. Hardware Token Profile (CCID/Smartcard)

### 11.1 Binding

Shares MAY be bound to hardware tokens using vendor attestation policies (informative).

### 11.2 PIN counters

Tokens **SHOULD** enforce monotonic PIN attempt counters.

### 11.3 Ephemeral ECDH

Session transport **SHOULD** use ephemeral ECDH for share delivery where tokens support it.

### 11.4 PIN exhaustion

On exhaustion, tokens **MUST** refuse further attempts and **SHOULD** zeroise protected share material per vendor policy.

---

## 12. Conformance Levels

| Level | Requirements |
|-------|--------------|
| **CESS-CORE** | Fixed layer + ChaCha20-Poly1305 + HKDF-BLAKE3 + Brainpool ECDH |
| **CESS-FULL** | CORE + RS profile + Serpent cascade option + hardware profile |
| **CESS-PQ** | FULL + hybrid PQ per Section 7 |

**Mode A outer wrapper:** Implementations that use **Mode A — fixed outer wrapper** (Section 8.2) **MUST** use the **normative** **construction** in Section 6.6: **ephemeral** **BrainpoolP384r1** ECDH, **HKDF-BLAKE3** to `K_outer`, **ChaCha20-Poly1305** **outer** AEAD, **outer** **plaintext** **`suite_id` || `inner_blob`** or **`suite_id` || `ed25519_signature` || `inner_blob`** when Ed25519 applies. This applies at **CESS-CORE** and higher when **Mode A** is enabled; **CESS-CORE** does **not** require **Mode B** or **BrainpoolP512r1** for that outer handshake.

---

## 13. Security Considerations

### 13.1 Side-channel and implementation hygiene

Implementations SHOULD follow side-channel guidance for Argon2, ECC, and symmetric crypto; use **constant-time** comparisons for tags and MACs; zeroise memory; follow air-gap procedures; protect biometric templates per local law; plan PQ migration per Section 7.

### 13.2 Metadata and traffic analysis (general)

Implementations SHOULD analyse metadata leakage beyond algorithm choice (timing, length, holder behaviour).

### 13.3 Cleartext cipher-suite identifiers and traffic analysis

**Risk:** If a **cipher suite identifier** or **algorithm discriminator** were transmitted **in cleartext** (for example a **16-bit** field prepended before encryption), an **interceptor** would immediately learn the **full inner profile**: symmetric cipher or cascade, ECDH curve class, inclusion of PQ hybrid, KDF usage, and authentication construction. That **collapses** the **wildcard** property of the cipher-agnostic layer: the deployment’s algorithm story becomes **public** to any passive observer.

**Traffic analysis:** **Repeated** use of the **same** cleartext discriminator across frames enables **session correlation**, **deployment fingerprinting**, and **tracking** of **profile rotations** over time, even when **payload** confidentiality holds.

**Normative mitigation:** Section 8 requires suite identifiers and profile metadata **inside** authenticated encryption (**Mode A**) or **omitted** on the wire when pre-negotiated (**Mode B**). **No** conforming implementation may expose these fields **outside** the authenticated boundary.

**Residual exposure:** **Outer** Mode A uses a **fixed** normative ChaCha20-Poly1305 shell; observers know that **outer** algorithm only, not **inner** profiles. The **12-byte** outer **nonce** is cleartext (Section 8.3) and MUST **not** carry **suite_id** or inner discriminators. **Length** of ciphertext and **timing** remain available to adversaries. **Mode A** ECDH **public keys** reveal **BrainpoolP384r1** for **outer** session establishment (Section 6.1.1), **not** inner suite choice.

### 13.4 Memory and tags

Sensitive intermediates SHOULD be zeroised (Section 6.5). Tags and MACs SHOULD be compared in **constant-time** where feasible.

### 13.5 Operational and legal context

Air-gap procedures (Section 9); coercion and organisational controls (`spec/GOVERNMENT.md`); biometric templates per local law.

### 13.6 Invalid inputs

Reject shares with failed MAC/AEAD verification; avoid leaking holder index through error channels (Section 8.7).

### 13.7 Logging

Operational logs SHOULD avoid recording raw key material or PINs.

### 13.8 Triple cascades and cascade diversity (informative)

A **triple** cascade (for example **`suite_id`** **`0x0007`**: ChaCha20-Poly1305 inner, Serpent-256-CTR + Poly1305 middle, Twofish-256-CTR + Poly1305 outer) provides **three** independent confidentiality layers with **no** shared design lineage across any pair. An adversary must break **all** **three** layers; there is **no** mathematical shortcut relating them. Performance cost grows **linearly** with the number of cascade layers; for the deployment contexts CESS targets (off-air key exchange, low-bandwidth radio, token operations), this cost is **acceptable** where policy requires maximum algorithmic diversity.

---

## 14. IANA / Registry Considerations

### 14.1 Error vocabulary (normative codes)

| Code | Meaning |
|------|---------|
| `AUTH_FAILED` | MAC/AEAD or PIN verification failed |
| `DUPLICATE_SHARE_INDEX` | Duplicate `x` or envelope identifier |
| `INSUFFICIENT_SHARES` | Fewer than `k` valid shares |
| `INTEGRITY_FAILURE` | BLAKE3 or transcript mismatch |
| `PIN_TOO_SHORT` | PIN below policy minimum |
| `PIN_EMPTY` | PIN missing |
| `INVALID_EC_POINT` | ECDH peer key invalid |
| `NONCE_REUSE` | Nonce collision detected |
| `CROSS_CURVE_REJECTED` | Curve mismatch |
| `INSUFFICIENT_SHARDS` | Reed–Solomon decode impossible |
| `INVALID_AEAD_INPUT` | Nonce length, key length, or other AEAD parameter invalid for the profile (e.g. RFC 8439 12-byte nonce) |

### 14.2 Identifiers

- **Suite IDs:** 16-bit unsigned values `0x0000`–`0xFFFF`; **`0x0000` reserved**. These values are **registry** and **implementation** identifiers for **off-wire** negotiation, documentation, and **authenticated plaintext** inside **Mode A** outer decryption (Section 8). They are **not** IANA-assigned cleartext **framing** fields on the wire and **MUST NOT** appear **outside** authenticated encryption (Section 8.1). The **numeric assignment table** is **`ALGORITHM-REGISTRY.md`** (**Cipher suite identifier lookup table**). **Normative** meaning is **lookup table** first; **informative** bit-field layout is in **Section 8.5**. **Unknown** values: **Section 8.5** (unknown **`suite_id`** handling).  
- **Envelope version:** 8-bit unsigned; carried **inside** **inner** plaintext (Mode A after inner decrypt, Mode B, or Section 8.2.1), **not** in **outer** plaintext and **not** as cleartext framing before decryption.

---

## Document revision history (informative)

| Date | Change |
|------|--------|
| 2026-04-06 | `suite_id` registry and outer-layer processing (Poly1305 before `suite_id`, unknown `suite_id`, oracle rules). Extended cipher tuple (optional keyed BLAKE3 integrity, optional Ed25519 signing); Twofish-256-CTR + Poly1305; standalone BLAKE3 integrity keys for inner profiles; Mode A outer plaintext with optional Ed25519 signature field; cascade registration rules (Section 4.4); extended `suite_id` encoding (Section 8.5); Section 13.8 triple cascades. |
| 2026-04-06 | Section 4.5: normative Ed25519 vs ECDH/KEM key separation (same session). |
| 2026-04-06 | Section 6.3: normative **`vectors/twofish.toml`** reference for Twofish-256-CTR + Poly1305 KATs (`cess-twofish-v0.2`). |

---

## Appendix A — Audit evidence summary (informative)

See `ALGORITHM-REGISTRY.md` for the living approved/excluded algorithm tables and the **cipher suite identifier lookup table** (`suite_id` assignments).

## Appendix B — Comparison with SLIP-0039, Feldman VSS, Pedersen VSS (informative)

- **SLIP-0039:** word-oriented encoding; CESS binary envelopes and **pre-transport** cipher negotiation differ; suite identifiers are **not** cleartext framing (Section 8).  
- **Feldman / Pedersen VSS:** provide verifiable shares; CESS v0.2 may be extended to include VSS in a future revision.

## Appendix C — Government procurement guidance (informative)

See `spec/GOVERNMENT.md`.

## Appendix D — Recommended reading

- RFC 5639, RFC 8439, RFC 9106  
- BSI TR-03111 (informative practices)  
- BLAKE3 specification; FrodoKEM specification; Classic McEliece specification  
- ENISA and NATO publications on key management (informative)
