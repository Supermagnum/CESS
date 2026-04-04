# CESS conformance test runner

Rust crate `cess-runner` (GNU GPL v3.0) loads and validates **TOML syntax** for all files under `vectors/`. Cryptographic **equality checks** against expected digests are intended to be wired to a **library under test** via `--impl` in future revisions.

## Build

```bash
cd runner
cargo build --release
```

Pinned dependencies are listed in `Cargo.toml` (reproducible builds).

## Wycheproof ChaCha20-Poly1305 harness

Independent of TOML parsing, the binary **`wycheproof_chacha`** runs the full **C2SP Wycheproof** JSON (`testdata/wycheproof/chacha20_poly1305_test.json`) against the `chacha20poly1305` crate:

```bash
cargo run --release --bin wycheproof_chacha -- ../testdata/wycheproof/chacha20_poly1305_test.json
```

Expect `total=325` and `fail=0`. This validates CESS’s ChaCha20-Poly1305 expectations against Google’s corpus.

## Brainpool ECDH harness (`rfc6932_brainpool`)

The binary **`rfc6932_brainpool`** checks **brainpoolP256r1** and **brainpoolP384r1** for any JSON file using the shared schema (`dA`, `x_qB`, `y_qB`, `x_Z`). Default file is RFC 6932 IKE examples; **RFC 7027** TLS vectors use the same schema:

```bash
env -u CARGO_TARGET_DIR cargo run --release --bin rfc6932_brainpool -- ../testdata/rfc6932/rfc6932_brainpool_ecdh.json
env -u CARGO_TARGET_DIR cargo run --release --bin rfc6932_brainpool -- ../testdata/rfc7027/rfc7027_brainpool_tls_ecdh.json
```

**P-512** and **P-224** are verified in Python (`scripts/rfc7027_brainpool.py`, `scripts/rfc6932_brainpool.py`, `brainpool_ecdh_common.py`). **RFC 5639** domain parameters: `scripts/rfc5639_brainpool_domain_parameters.py`.

## Usage

```bash
./target/release/cess-runner --level core --vectors ../vectors
./target/release/cess-runner --level full --vectors ../vectors --impl /path/to/libcess.so
./target/release/cess-runner --level pq --vectors ../vectors
```

### Flags

| Flag | Values | Meaning |
|------|--------|---------|
| `--level` | `core`, `full`, `pq` | Selects which conformance level to enforce when crypto checks are enabled |
| `--vectors` | directory path | Location of `*.toml` vectors (default: `../vectors` relative to crate) |
| `--impl` | path | Optional path to the implementation under test (shared library or CLI); if missing, runner may SKIP binding tests |

## Output format

- One line per vector file: `PASS parse <file>` or `FAIL parse <file>`.  
- Final summary: `summary PASS=n FAIL=m`.  
- Exit code **0** only if every listed file parses as TOML.

When full verification is implemented, each subtest will emit `PASS`, `FAIL`, or `SKIP` per vector entry.

## Conformance

See root `CONFORMANCE.md` for claiming CESS-CORE, CESS-FULL, or CESS-PQ compliance.
