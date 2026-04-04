# CESS — Cryptologically Enchanted Shamir's Secret

**Version:** 0.1-draft  
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
| SLIP-0039 | Informative; CESS uses binary share envelopes and different cipher negotiation; mnemonic encoding is out of scope. |
| RFC 5639 | Normative for Brainpool curves. |
| BSI TR-03111 | Informative/normative practices for ECC key generation and validation alongside RFC 5639. |
| Feldman VSS (1987) | Informative; CESS does not mandate verifiable secret sharing in v0.1. |
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
- **Holder anonymity** when envelope design conceals metadata (Section 8).  
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

Implementations MUST advertise supported tuples as a **list of cipher suite identifiers** (Section 8.2). Peers MUST select the **highest mutually preferred** suite or abort.

### 4.6 Upgrade path

**Version** field in the share envelope (Section 8) governs format evolution. Implementations MUST reject unknown major versions.

---

## 5. Fixed Layer Specification

### 5.1 Shamir’s Secret Sharing over GF(2^8)

**Field:** GF(2^8) with reduction polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B), identical to the AES field.

**Polynomial:** For threshold `k`, coefficients `a_0 .. a_{k-1}` with `a_0` = secret byte; random `a_1..a_{k-1}` uniformly in GF(2^8) for enrollment randomness.

**Shares:** For `i = 1 .. n`, `x_i = i` (as field element); `y_i = f(x_i)`. Implementations MUST use **non-zero** `x` values.

**Reconstruction:** Lagrange interpolation at `x=0` (see test vectors).

**Share format:** See Section 8 (envelope).

**Holder anonymity:** Implementations SHOULD NOT embed `k`, `n`, or human-readable indices in plaintext metadata. Duplicate detection MUST use **constant-time** or **oblivious** comparisons where feasible (Section 8.4).

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

Implementations MUST support **BrainpoolP384r1** and **BrainpoolP512r1** ECDH per RFC 5639.

**Key generation:** Private scalars MUST be uniformly random in `[1, n-1]`.

**ECDH:** Shared secret is the **x-coordinate** of the shared point, **32-byte** or **48-byte** fixed-length encoding per implementation profile — implementations MUST document encoding and use it consistently with test vectors.

**Point validation:** Incoming public points MUST be validated; **invalid curve points MUST be rejected** (including point at infinity, wrong curve, wrong order).

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

### 7.3 Feature gating

PQ features MUST be **off by default** until explicitly enabled; UI and logs MUST warn about **size and performance** impact.

### 7.4 Audit tracking

Deployments SHOULD record PQ algorithm versions and audit report identifiers in configuration management.

---

## 8. Share Format

### 8.1 Envelope (normative structure)

| Field | Size | Description |
|-------|------|-------------|
| `version` | 1 byte | Format version (current: `0x01`) |
| `suite_id` | 2 bytes | Cipher suite identifier |
| `opaque_payload` | variable | Encrypted share body (includes `y`; may conceal `x` via packaging) |
| `mac` | 32 bytes | BLAKE3-MAC over preceding fields with domain separation key |

Implementations MAY encrypt `x` inside `opaque_payload` to support holder anonymity.

### 8.2 Cipher suite identifier registry

Maintained in `ALGORITHM-REGISTRY.md` and Section 14.

### 8.3 Metadata concealment

Plaintext metadata that reveals `k`, `n`, or index SHOULD NOT be transmitted unencrypted.

### 8.4 Duplicate share detection

Implementations MUST detect duplicate shares without leaking index through error messages (constant-time compare of cryptographic digests).

---

## 9. Enrollment Protocol

### 9.1 Air-gap requirement

**Normative:** Root secret generation and initial splitting **SHOULD** occur on an **air-gapped** system with audited software supply chain.

### 9.2 Entropy

CSPRNG seed **MUST** meet platform requirements (hardware RNG where available).

### 9.3 Session key generation

Session keys **MUST** be derived per Section 6.2 after authenticated ECDH (and optional PQ).

### 9.4 Encryption sequence

Encrypt source material with selected AEAD; verify integrity tags before splitting.

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

Collect at least `k` shares; authenticate holders (PIN, optional biometric per deployment); detect duplicates; reconstruct polynomial; decrypt layers; verify BLAKE3 and AEAD tags; zeroise intermediates.

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

---

## 13. Security Considerations

### 13.1–13.7

Implementations SHOULD follow side-channel guidance for Argon2, ECC, and symmetric crypto; use **constant-time** comparisons for tags and MACs; zeroise memory; follow air-gap procedures; protect biometric templates per local law; analyse metadata leakage; plan PQ migration per Section 7.

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

- **Suite IDs:** 16-bit unsigned, `0x0000` reserved.  
- **Envelope version:** 8-bit unsigned.

---

## Appendix A — Audit evidence summary (informative)

See `ALGORITHM-REGISTRY.md` for the living table.

## Appendix B — Comparison with SLIP-0039, Feldman VSS, Pedersen VSS (informative)

- **SLIP-0039:** word-oriented encoding; CESS binary envelopes and cipher negotiation differ.  
- **Feldman / Pedersen VSS:** provide verifiable shares; CESS v0.1 may be extended to include VSS in a future revision.

## Appendix C — Government procurement guidance (informative)

See `spec/GOVERNMENT.md`.

## Appendix D — Recommended reading

- RFC 5639, RFC 8439, RFC 9106  
- BSI TR-03111 (informative practices)  
- BLAKE3 specification; FrodoKEM specification; Classic McEliece specification  
- ENISA and NATO publications on key management (informative)
