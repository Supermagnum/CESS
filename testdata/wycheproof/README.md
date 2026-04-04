# Wycheproof test data (vendored)

This directory contains a **single-file** excerpt from [C2SP/wycheproof](https://github.com/C2SP/wycheproof):

- `chacha20_poly1305_test.json` — ChaCha20-Poly1305 AEAD vectors (`testvectors_v1/chacha20_poly1305_test.json` in upstream).

**Upstream licence:** Apache License 2.0 (see [Wycheproof LICENSE](https://github.com/C2SP/wycheproof/blob/master/LICENSE)).

**CESS use:** The Rust binary `runner` / `wycheproof_chacha` loads this JSON and verifies every case against the `chacha20poly1305` crate (same family as CESS primary bulk AEAD). This cross-checks CESS’s ChaCha20-Poly1305 expectations against an independent, widely used test corpus.

**Regeneration:** Replace the JSON from a pinned Wycheproof commit and re-run:

```bash
cd runner && cargo run --release --bin wycheproof_chacha -- ../testdata/wycheproof/chacha20_poly1305_test.json
```

Expected: `fail=0` and `total=325` (as of the vendored file).
