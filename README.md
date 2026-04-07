![Open Invention Network member](OIN/oin-member-horiz.jpg)

# CESS — Cryptologically Enchanted Shamir's Secret

**Version:** 0.2
**Status:** Specification only (normative text and test vectors)

This project is registered with the [Open Invention Network](https://openinventionnetwork.com/) (OIN), a defensive patent pool protecting Linux-related open source software. The combination of open preprint publication (establishing prior art), OIN membership, and GPL-3.0 licensing is intended to ensure this technology remains freely available and cannot be proprietised or restricted by any state or commercial actor.

CESS is an open cryptographic standard for **threshold secret sharing** combined with **cipher-agnostic authenticated encryption**, **password-based share wrapping**, and optional **post-quantum hybrid key exchange**. It is designed for deployments that require long-lived confidentiality, air-gapped enrollment, hardware token binding, and procurement paths independent of NSA/NIST-only algorithm baselines.

## Why CESS exists

Existing ecosystems address parts of this problem but leave gaps:

- **GnuPG** provides strong encryption and signing, but not a normative, interoperable profile for Shamir shares plus modern AEAD and cross-jurisdiction escrow workflows.
- **Autocrypt** focuses on opportunistic mail encryption, not threshold splitting of long-term secrets with PIN-wrapped shares.
- **SLIP-0039** standardises mnemonic encoding of Shamir shares for seeds; CESS complements this space with a **binary share envelope**, explicit **cipher negotiation**, **Brainpool ECDH** profiles, **Argon2id**-based PIN handling, and **CESS-PQ** hybrid combiners.

CESS defines the **standard**; [**SplitDisk**](https://github.com/Supermagnum/splitdisk) (and similar products) are **reference scenarios** and example deployments, not the standard itself.

## Cipher-agnostic design

CESS fixes **Shamir's Secret Sharing over GF(2^8)** and several audited **non-optional** integrity and password primitives. All **bulk encryption, KEM, KDF, and MAC** layers are **selectable** from an audited registry, subject to the **two independent auditor** rule and the **hard exclusion list** (see `spec/CESS-v0.2.md` and `ALGORITHM-REGISTRY.md`).

## Audit requirement and exclusions (summary)

- Every primitive in the cipher-agnostic layer MUST have **two or more** independent evaluations from the qualifying auditor list (NESSIE, CRYPTREC, ECRYPT/eSTREAM, IACR peer review, BSI, NCC Group, Cure53, Kudelski Security, JP Aumasson, PHC committee).
- **NSA design input**, **NIST/FIPS-only** review, and several algorithms (AES, SHA-2, SHA-3, NIST curves, ML-Kyber, Dual_EC_DRBG, RC4, DES, 3DES, HMAC-SHA-*) are **excluded** with explicit rationale in the specification.
- **X25519 / Ed25519** are optionally permitted with documented rationale (Bernstein designs; extensive independent audits).

Details: `spec/CESS-v0.2.md` Section 3, `spec/CRYPTO.md`, and `ALGORITHM-REGISTRY.md`.

## Repository layout

| Path | Role |
|------|------|
| `spec/CESS-v0.2.md` | Main normative standard (RFC 2119 keywords) |
| `spec/CRYPTO.md` | Cryptographic rationale and proof sketches |
| `spec/GOVERNMENT.md` | Government and high-security deployment notes |
| `ALGORITHM-REGISTRY.md` | Living registry of approved and excluded algorithms |
| `vectors/` | Machine-readable test vectors (TOML: ChaCha/Serpent/Twofish bulk, integration, etc.); CC0 |
| `testdata/wycheproof/` | Vendored Wycheproof ChaCha20-Poly1305 JSON (Apache-2.0 upstream); see `testdata/wycheproof/README.md` |
| `scripts/` | Vector generation helpers (GPL-3.0 where code) |
| `runner/` | Conformance test runner (Rust, GPL-3.0) |
| `LICENSE-SPEC` | CC0 1.0 — specification and vectors |
| `LICENSE-CODE` | GPL-3.0 — code |
| `PATENTS.md` | OIN context and contributor patent non-assertion covenant |
| `CONTRIBUTING.md` | Contribution rules and review policy |
| `CONFORMANCE.md` | How to claim and document conformance |
| `IMPLEMENTATIONS.md` | Optional listing of conforming products |

## Licensing

| Content | Licence |
|---------|---------|
| Specification prose (`spec/*.md`), `README.md`, `ALGORITHM-REGISTRY.md`, `vectors/*.toml` | **CC0 1.0 Universal** (public domain dedication) — see `LICENSE-SPEC` |
| Rust runner, reference implementations, `scripts/serpent_helper/` | **GNU GPL v3.0** — see `LICENSE-CODE` |

## Patents and OIN

Contributors agree to the **patent non-assertion covenant** in `PATENTS.md`. The project is registered with the [Open Invention Network](https://openinventionnetwork.com/) (OIN), a defensive patent pool for Linux-related open source software. Cross-licensing through OIN does **not** by itself cover parties outside that ecosystem; the **covenant** is intended to close that gap for conforming implementations.

## Audiences

- Cryptographers and protocol engineers  
- Government agencies and defence contractors (especially EU-centric procurement)  
- Hardware security token and smartcard vendors (CCID profile)  
- Open-source developers building threshold custody and disaster-recovery tooling  

## Contributing

See `CONTRIBUTING.md`. **Pull requests** are treated as agreement to `PATENTS.md`. Specification changes require **two reviewers in different countries**. New algorithms use `ALGORITHM-REGISTRY.md` (open a PR against the registry, then against `spec/CESS-v0.2.md` cross-references if needed).

### Adding a cipher to the registry

1. Confirm **two qualifying audits** and absence of **hard exclusions**.  
2. Open a PR editing `ALGORITHM-REGISTRY.md` (evidence table, identifier allocation).  
3. Add or extend test vectors under `vectors/` covering the new suite.  
4. Obtain two maintainer reviews per `CONTRIBUTING.md`.

## Document index

- [Main standard](spec/CESS-v0.2.md)  
- [CRYPTO (rationale)](spec/CRYPTO.md)  
- [GOVERNMENT (deployment)](spec/GOVERNMENT.md)  
- [Algorithm registry](ALGORITHM-REGISTRY.md)  
- [Conformance](CONFORMANCE.md)  
- [Vectors guide](vectors/README.md)  
- [Test runner](runner/README.md)  
- [Patents](PATENTS.md)  

## Relationship to SplitDisk

**CESS** is the **standard**. [**SplitDisk**](https://github.com/Supermagnum/splitdisk) is an example **implementation scenario** (e.g. disk encryption plus share distribution); the tool specification lives in that repository. Products may claim **CESS-CORE**, **CESS-FULL**, or **CESS-PQ** conformance per `CONFORMANCE.md` without using the SplitDisk name.
