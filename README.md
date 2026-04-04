# CESS — Cryptologically Enchanted Shamir's Secret

**Version:** 0.1-draft  
**Status:** Specification only (normative text and test vectors)

CESS is an open cryptographic standard for **threshold secret sharing** combined with **cipher-agnostic authenticated encryption**, **password-based share wrapping**, and optional **post-quantum hybrid key exchange**. It targets long-lived confidentiality, air-gapped enrollment, hardware token binding, and procurement paths outside NSA/NIST-only algorithm baselines.

## Where everything lives

All specification text, vectors, licences, and tooling are under **[`cess-standard/`](cess-standard/)**. Start with the full project overview:

- **[`cess-standard/README.md`](cess-standard/README.md)** — complete introduction, layout table, licensing, contributing, and [SplitDisk](https://github.com/Supermagnum/splitdisk) relationship

## Quick links (from repo root)

| Document | Path |
|----------|------|
| Main standard | [`cess-standard/spec/CESS-v0.1.md`](cess-standard/spec/CESS-v0.1.md) |
| Cryptographic rationale | [`cess-standard/spec/CRYPTO.md`](cess-standard/spec/CRYPTO.md) |
| Algorithm registry | [`cess-standard/ALGORITHM-REGISTRY.md`](cess-standard/ALGORITHM-REGISTRY.md) |
| Conformance | [`cess-standard/CONFORMANCE.md`](cess-standard/CONFORMANCE.md) |
| Contributing | [`cess-standard/CONTRIBUTING.md`](cess-standard/CONTRIBUTING.md) |
| Style guide (AI and human) | [`cess-standard/STYLE-GUIDE.md`](cess-standard/STYLE-GUIDE.md) |
| Vectors | [`cess-standard/vectors/README.md`](cess-standard/vectors/README.md) |
| Conformance runner | [`cess-standard/runner/README.md`](cess-standard/runner/README.md) |

## Licence summary

Specification and vectors: **CC0 1.0** ([`cess-standard/LICENSE-SPEC`](cess-standard/LICENSE-SPEC)). Code (runner, scripts): **GPL-3.0** ([`cess-standard/LICENSE-CODE`](cess-standard/LICENSE-CODE)). See [`cess-standard/README.md`](cess-standard/README.md) for the full table.
