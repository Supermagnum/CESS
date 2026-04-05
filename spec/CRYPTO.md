# CESS cryptographic rationale (informative)

**Version:** 0.2-draft  

This document explains **why** CESS selects specific primitives, **why** excluded algorithms are rejected, and gives **argument sketches** for composition security. It is **not** normative; `spec/CESS-v0.2.md` is authoritative.

## 1. Primitive choices

### 1.1 Shamir over GF(2^8)

Shamir’s scheme over a finite field provides **information-theoretic** security for the secret byte given uniform random polynomial coefficients and distinct non-zero evaluation points. GF(2^8) matches ubiquitous **byte-oriented** implementations and aligns with **Reed–Solomon** and **BLAKE3** processing widths.

### 1.2 Argon2id (RFC 9106)

Argon2id won the **Password Hashing Competition** and resists **side-channel** and **GPU** attacks better than bcrypt/scrypt for high memory factors. The CESS profile (65536 KiB, 3 iterations, parallelism 4) targets **hardware-assisted** attackers while remaining deployable on modern servers.

### 1.3 BLAKE3

BLAKE3 offers **high throughput**, **tree** hashing for parallelism, and **keyed MAC** modes with audits by **NCC Group** and **Kudelski**, without NSA design involvement in the round function choice comparable to AES/SHA-2 history.

### 1.4 Brainpool ECDH (RFC 5639)

Brainpool curves are **verifiably** generated without NSA “magic constants” in the same sense as NIST curves; **BSI TR-03111** references Brainpool for government-grade ECC. Point validation prevents **invalid curve** and **small-subgroup** attacks.

### 1.4.1 Mode A outer session anchor (informative)

The **Mode A** outer wrapper is **explicitly**: **ephemeral** BrainpoolP384r1 ECDH; **HKDF-BLAKE3** with `info = cess-outer-envelope-v1` to a 32-byte **`K_outer`**; **ChaCha20-Poly1305** keyed by **`K_outer`**; **outer** plaintext = **16-bit** `suite_id` (big-endian) **||** `inner_blob` (Section 6.6 of `spec/CESS-v0.2.md`). The classical ECDH step is **fixed** to BrainpoolP384r1 (Section 6.1.1). **Every** primitive in that stack is already approved in the registry; **no** new dependencies are introduced. Rationale for P384 only: the curve is already in the approved registry as a classical KEM; it is **BSI**-aligned with no NSA-designed parameters; it offers roughly **192-bit** classical security in a lighter package than BrainpoolP512r1 while remaining stronger than P-256-class curves; anchoring the mandatory outer layer on one registry-approved curve gives a single audited interoperability point for all CESS Mode A sessions.

### 1.5 ChaCha20-Poly1305 (RFC 8439)

ChaCha20 is an **eSTREAM**-related design with extensive analysis; Poly1305 is a **one-time** authenticator suitable for AEAD composition. Together they avoid AES and SHA-2 exclusions.

### 1.6 Serpent-256-CTR + Poly1305

Serpent was an **AES finalist** with NESSIE background; in CTR mode with an independent Poly1305 key, confidentiality reduces to **PRP** assumptions on Serpent; integrity reduces to **Poly1305** unforgeability under nonce/key uniqueness.

## 2. Excluded algorithms (per-algorithm)

| Algorithm | Reason |
|-----------|--------|
| AES | NSA-designed S-box; excluded regardless of mode. |
| SHA-2 | NSA-designed digest family. |
| SHA-3 | NSA competition involvement is disqualifying for CESS audit policy. |
| NIST curves | Historical NSA involvement in curve selection. |
| ML-KEM | NIST PQC process excluded by policy. |
| Dual_EC_DRBG | Backdoored DRBG. |
| RC4/DES/3DES | Broken or deprecated. |
| HMAC-SHA-* | Depends on excluded hash. |

## 3. Optional X25519 / Ed25519

Curve25519 designs are **not** NSA-produced; audits by independent researchers predate broad NIST adoption. Implementations using X25519/Ed25519 MUST document that **conformance** to CESS bulk/KDF layers still uses approved AEAD and integrity primitives.

## 4. Cascade construction (security argument)

Let `P` be plaintext; `K1` ChaCha key; `K2` Serpent key; `T` inner tag.

- Inner: `C1 = AEAD_ChaCha(K1; P)`.  
- Outer: `C2 = Serpent_CTR(K2; C1)`; `T2 = Poly1305(K_poly; AAD || C2)`.

An attacker must either **forge** `T2` without keys, or **decrypt** Serpent without `K2`, or **forge** ChaCha AEAD without `K1`. Keys MUST be **independent** (derived with distinct labels).

## 5. HKDF-BLAKE3 combiner

HKDF is proven in the **random oracle** model when the PRF is **HMAC** with a collision-resistant hash. Replacing the hash with **HMAC-BLAKE3** assumes **BLAKE3** behaves as a **PRF** in the HMAC construction; this is the standard **engineer’s assumption** for modern hashes. Hybrid `classical || pq` follows the **concatenation** combiner pattern analysed for TLS-like KDFs; **quantum** security requires PQ KEM assumptions on the PQ component.

## 6. SSS information-theoretic sketch

Secret `s = a_0`. Coefficients `a_1..a_{k-1}` uniform. For any `k-1` shares, the conditional distribution of `s` given those shares is **uniform** (for standard Shamir over a field). Hence **unbounded** adversary with `k-1` shares learns **nothing** about `s`.

## 7. Holder anonymity (argument)

If `x` and quorum metadata are **encrypted** inside the envelope under **holder-specific** keys or transmitted only via **out-of-band** pairing, passive holders may not learn global `k`/`n`. **Side channels** (timing of operations, QR payload sizes) remain **implementation** issues.

## 8. Post-quantum threat model and migration

- **Harvest now, decrypt later** motivates **PQ KEM** hybridisation.  
- **ML-KEM excluded** per policy; **FrodoKEM** and **Classic McEliece** are candidates with non-NIST-primary-track histories or long academic scrutiny.  
- **Migration:** deploy **hybrid** sessions first; retain classical shares until PQ confidence increases.

## 9. References (informative)

- Shamir, “How to Share a Secret,” 1979.  
- Feldman, “A Practical Scheme for Non-interactive Verifiable Secret Sharing,” 1987.  
- Pedersen, “Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing,” 1992.  
- RFC 5869, RFC 8439, RFC 9106, RFC 5639.  
- BLAKE3 specification; FrodoKEM; Classic McEliece documentation.
