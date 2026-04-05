# CESS — Cryptologically Enchanted Shamir's Secret

**Version:** 0.2-draft  
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
| SLIP-0039 | Informative; CESS uses binary share envelopes and **off-wire** cipher negotiation (Section 4.5); suite identifiers are **not** cleartext framing (Section 8); mnemonic encoding is out of scope. |
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
- **Cipher-agnostic layer:** KEM, KDF, AEAD, and optional PQ KEM selected from the Algorithm Registry.  
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

**X25519 / Ed25519** MAY be used only where deployment documentation states: independent audits predate or exceed reliance on later NIST standardisation; curve design is attributed to **Bernstein** et al., not NSA.

---

## 4. Cipher-Agnostic Architecture

### 4.1 Layer model

1. **Fixed layer (mandatory):** GF(2^8) Shamir; Argon2id; BLAKE3; Reed–Solomon profile.  
2. **Cipher-agnostic layer (selectable):** Brainpool ECDH; HKDF-BLAKE3; AEAD tuple; optional PQ KEM + hybrid combiner.

### 4.2 Cipher tuple

A **cipher tuple** is an ordered selection:

`(classical_kem, kdf, bulk_aead [, pq_kem])`

### 4.3 Compliant examples (informative)

- ChaCha20-Poly1305 alone.  
- Serpent-256-CTR + Poly1305 alone.  
- ChaCha inner, Serpent+Poly1305 outer (cascade).  
- Brainpool ECDH + HKDF-BLAKE3 + tuple above.  
- Optional: FrodoKEM-1344 + classical + HKDF-BLAKE3 hybrid.

### 4.4 Cascade rules

When cascading AEADs, implementations MUST define **order** (inner vs outer). CESS default: **inner = ChaCha20-Poly1305**, **outer = Serpent-256-CTR + Poly1305** on the inner ciphertext. Both layers MUST use **distinct keys** derived per Section 6.

### 4.5 Cipher negotiation

Implementations MUST advertise supported tuples as a **list of cipher suite identifiers** (Section 8.5, `ALGORITHM-REGISTRY.md`) during **secure pre-transport** negotiation (authenticated session establishment, enrollment ceremony, or other **out-of-band** agreement). Peers MUST select the **highest mutually preferred** suite or abort.

Implementations MUST **not** encode negotiated suite choice as **cleartext** framing on the wire (Section 8.1).

### 4.6 Upgrade path

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

**Cascade:** Inner ChaCha20-Poly1305 on plaintext; outer Serpent-CTR then Poly1305 on inner ciphertext; **distinct** subkeys.

### 6.4 PIN-derived key wrapping

1. Argon2id output (32 bytes) as IKM.  
2. HKDF-BLAKE3 with `info = "cess-pin-v1"` → 32-byte wrap key.  
3. AEAD encrypt share material (ChaCha20-Poly1305 or Serpent profile).

### 6.5 Session key material

Session keys MUST be **32 bytes** unless a profile explicitly uses 64-byte expanded keys. **Sensitive intermediates MUST be zeroised** (Section 13.3).

### 6.6 Normative outer wrapper construction (Mode A)

When **Mode A — fixed outer wrapper** (Section 8.2) is used, the **outer** layer **MUST** be built **exactly** from the following **registry-approved** components (no additional algorithms):

1. **Outer key agreement:** **Ephemeral** **BrainpoolP384r1** ECDH per Section 6.1.1, producing `classical_shared_secret`.  
2. **Outer KDF:** **HKDF-BLAKE3** per Section 6.2: **IKM** = `classical_shared_secret`, **or** `classical_shared_secret || pq_shared_secret` when CESS-PQ applies (classical part **always** from step 1, concatenation order per Section 7.2); **salt** as in Section 6.2; **info** = UTF-8 `cess-outer-envelope-v1`; **output length** **32 bytes** → **`K_outer`**.  
3. **Outer AEAD:** **ChaCha20-Poly1305** per Section 6.3 and RFC 8439; **key** = `K_outer`; **12-byte** nonce; **AAD** empty unless a **registered** deployment profile defines non-empty AAD.  
4. **Outer AEAD plaintext:** **Exactly** the **16-bit** cipher suite identifier **`suite_id`** (**big-endian**) **concatenated** with **`inner_blob`**, where **`inner_blob`** is the **inner** ciphertext (variable length) produced by the **selected** inner profile. **Outer** plaintext **MUST** consist **solely** of **`suite_id` || `inner_blob`**; the envelope **version** byte **MUST NOT** appear in **outer** plaintext. Envelope **version** **MUST** be carried **inside** the **inner** plaintext after inner decryption (Section 8.3).

**Informative:** This construction uses **only** primitives already listed in `ALGORITHM-REGISTRY.md` (classical KEM, KDF, primary AEAD); it introduces **no** new dependencies and keeps the outer wrapper **auditable** and consistent with the registry’s security philosophy.

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

**Mode A — Fixed outer wrapper (in-band suite after decryption):** Parties perform **ephemeral** **BrainpoolP384r1** ECDH per Section 6.1.1, then build the **outer** wrapper per Section 6.6 (and optional PQ hybrid in the **outer** KDF IKM). The **wire** carries **only** the **outer** AEAD output (Section 8.3). **Plaintext** of the outer AEAD is **`suite_id` || `inner_blob`** (Section 6.6). **Interceptors** without `K_outer` learn **nothing** about `suite_id` or inner algorithms.

**Mode B — Profile pre-negotiation (no in-band identifier):** The full cipher tuple (or equivalent profile reference) is agreed **out-of-band** (enrollment, ceremony, pre-configured policy) or over a **separate** authenticated channel **before** the ciphertext frame is emitted. Implementations MUST **not** place `suite_id` or **any** algorithm discriminator in the transmitted frame. The wire carries **only** ciphertext produced under the **pre-agreed** profile (and optional minimal framing agreed in that same pre-negotiation).

**PIN-only** or **offline** share storage without ECDH MUST use **Mode B** (suite fixed at enrollment) unless a **separate** key-establishment step supplies `K_outer` for **Mode A**.

#### 8.2.1 Out-of-band session key and cipher profile

When **session key material** and the **full cipher profile** are established **entirely out-of-band** (informative examples: **GR-K-GDSS** and **Galdralag** ephemeral ECDH flows, as defined by those deployments), the **in-band** **16-bit** suite identifier is **optional** and need not be transmitted. Implementations **MAY** use **Mode B** (or equivalent **inner-only** framing) with **no** `suite_id` on the wire.

**Normative:** If **any** `suite_id` or profile metadata is transmitted **in-band**, it **MUST** be protected by the **Mode A** outer wrapper (Section 6.6): ephemeral BrainpoolP384r1 ECDH, HKDF-BLAKE3 to `K_outer`, ChaCha20-Poly1305, with outer plaintext `suite_id` || `inner_blob` as defined in Section 8.3. **Implementations MUST NOT** expose a cleartext suite identifier outside that authenticated boundary (Section 8.1).

### 8.3 Mode A: outer ciphertext (normative)

The **outer** layer MUST be **ChaCha20-Poly1305** (RFC 8439): **32-byte** key `K_outer`, **12-byte** nonce, ciphertext and **16-byte** tag per the RFC data model.

After decryption, if `suite_id` is **`0x0000`**, implementations MUST **reject** the envelope (`suite_id` is reserved; Section 14.2).

**On the wire:**

| Field | Size | Description |
|-------|------|-------------|
| `outer_nonce` | 12 bytes | Nonce; implementations MUST ensure **nonce uniqueness** per `K_outer` (random or deterministic counter per deployment policy). |
| `outer_ciphertext` | variable | Ciphertext concatenated with Poly1305 tag (RFC 8439). |

**Outer plaintext** (input to ChaCha20-Poly1305 encryption, **AAD** empty unless a deployment profile sets registered AAD) **MUST** be **exactly**:

| Field | Size | Description |
|-------|------|-------------|
| `suite_id` | 2 bytes | Big-endian **16-bit** cipher suite identifier (`ALGORITHM-REGISTRY.md`) |
| `inner_blob` | variable | **Inner** ciphertext from the **selected** inner profile (AEAD tuple, cascade, BLAKE3-MAC inside inner layer as specified for that suite). **Envelope** **version** (Section 4.6) **MUST** appear **inside** the **plaintext** **protected** **by** **the** **inner** **layer** **after** **inner** **decryption** (e.g. first byte of inner plaintext per inner suite), **not** in **outer** plaintext.

**Inner** keys MUST be derived from the same ECDH (and optional PQ) IKM as `K_outer` using **distinct** HKDF-BLAKE3 `info` values that **uniquely** identify the negotiated suite (e.g. UTF-8 `cess-inner-` concatenated with the **16-bit** `suite_id` encoded in **big-endian** hex). Implementations MUST **not** derive inner keys until `suite_id` is obtained from **authenticated** outer plaintext or from **Mode B** / **Section 8.2.1** pre-negotiation state.

Implementations MAY encrypt Shamir coordinate `x` and metadata inside `inner_blob` to support holder anonymity.

### 8.4 Mode B: pre-negotiated inner only (normative)

The transmitted object is **only** `inner_blob`: authenticated encryption under the **pre-agreed** profile. **No** `suite_id` field appears on the wire. **Version** and share fields reside **inside** the inner plaintext or authenticated data as defined in the deployment profile. **Inner** keys MUST be derived per the **pre-agreed** profile: when IKM comes from ECDH, use the **same** HKDF-BLAKE3 `info` pattern as Section 8.3 with `suite_id` from **configuration**; when IKM comes from PIN wrap or enrollment-only material, use Section 6.4 or a **documented** profile that **never** places `suite_id` in cleartext. Fully **out-of-band** key and profile agreement (Section 8.2.1) **MAY** omit **both** **Mode A** **outer** **wrapper** **and** **in-band** **`suite_id`** when **no** **identifier** **is** **sent** **in-band**.

### 8.5 Cipher suite identifier registry

The **16-bit** registry (`ALGORITHM-REGISTRY.md`, Section 14) is an **internal** mapping for implementations, documentation, and **plaintext** use **inside** Mode A outer decryption or **off-wire** negotiation. It is **not** a cleartext **framing** field visible to third parties.

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

**Mode A outer wrapper:** Implementations that use **Mode A — fixed outer wrapper** (Section 8.2) **MUST** use the **normative** **construction** in Section 6.6: **ephemeral** **BrainpoolP384r1** ECDH, **HKDF-BLAKE3** to `K_outer`, **ChaCha20-Poly1305** **outer** AEAD, **outer** **plaintext** **`suite_id` || `inner_blob`**. This applies at **CESS-CORE** and higher when **Mode A** is enabled; **CESS-CORE** does **not** require **Mode B** or **BrainpoolP512r1** for that outer handshake.

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

- **Suite IDs:** 16-bit unsigned values `0x0000`–`0xFFFF`; **`0x0000` reserved**. These values are **registry** and **implementation** identifiers for **off-wire** negotiation, documentation, and **authenticated plaintext** inside **Mode A** outer decryption (Section 8). They are **not** IANA-assigned cleartext **framing** fields on the wire and **MUST NOT** appear **outside** authenticated encryption (Section 8.1).  
- **Envelope version:** 8-bit unsigned; carried **inside** **inner** plaintext (Mode A after inner decrypt, Mode B, or Section 8.2.1), **not** in **outer** plaintext and **not** as cleartext framing before decryption.

---

## Appendix A — Audit evidence summary (informative)

See `ALGORITHM-REGISTRY.md` for the living table.

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
