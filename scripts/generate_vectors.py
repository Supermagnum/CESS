#!/usr/bin/env python3
"""Generate all CESS v0.2 TOML test vectors. Run: .venv/bin/python scripts/generate_vectors.py"""
from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
from itertools import combinations
from pathlib import Path

import argon2
import blake3
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.poly1305 import Poly1305

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SERPENT_HELPER_RELEASE = SCRIPT_DIR / "serpent_helper/target/release/serpent_helper"
SERPENT_HELPER_DEBUG = SCRIPT_DIR / "serpent_helper/target/debug/serpent_helper"


def serpent_helper_exe() -> Path:
    for p in (SERPENT_HELPER_RELEASE, SERPENT_HELPER_DEBUG):
        if p.is_file():
            return p
    ct = os.environ.get("CARGO_TARGET_DIR")
    if ct:
        for p in (Path(ct) / "release/serpent_helper", Path(ct) / "debug/serpent_helper"):
            if p.is_file():
                return p
    raise FileNotFoundError(
        "serpent_helper binary not found; build with: "
        "cd scripts/serpent_helper && cargo build --release --target-dir ./target"
    )


def serpent_ctr_bytes(key32: bytes, iv16: bytes, plaintext: bytes) -> bytes:
    """Serpent-256-CTR using the Rust helper (must match CESS reference)."""
    exe = serpent_helper_exe()
    kh = key32.hex()
    ivh = iv16.hex()
    if len(plaintext) > 262144:
        r = subprocess.run([str(exe), kh, ivh, "-"], input=plaintext, capture_output=True, check=True)
    else:
        r = subprocess.run([str(exe), kh, ivh, plaintext.hex()], capture_output=True, check=True)
    return bytes.fromhex(r.stdout.decode().strip())


def poly1305_tag_rfc8439(key32: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Poly1305 MAC input per RFC 8439 section 2.8 (standalone 32-byte key)."""

    def pad16(a: bytes) -> bytes:
        return a + b"\x00" * ((-len(a)) % 16)

    mac_data = pad16(aad) + pad16(ciphertext) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    return Poly1305.generate_tag(key32, mac_data)

# --- GF(2^8) AES field ---
POLY = 0x11B


def gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= POLY & 0xFF
        b >>= 1
    return p


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError
    x = a
    for _ in range(6):
        x = gf_mul(x, x)
        x = gf_mul(x, a)
    return x


def gf_div(a: int, b: int) -> int:
    return gf_mul(a, gf_inv(b))


def poly_eval(coeffs: list[int], x: int) -> int:
    acc = 0
    xp = 1
    for c in coeffs:
        acc ^= gf_mul(c, xp)
        xp = gf_mul(xp, x)
    return acc


def lagrange_interpolate(xs: list[int], ys: list[int]) -> int:
    k = len(xs)
    secret = 0
    for i in range(k):
        num = 1
        den = 1
        xi = xs[i]
        for j in range(k):
            if i == j:
                continue
            xj = xs[j]
            num = gf_mul(num, xj)
            den = gf_mul(den, xi ^ xj)
        li0 = gf_div(num, den)
        secret ^= gf_mul(ys[i], li0)
    return secret


def shamir_split(secret_byte: int, k: int, n: int, rand_coeffs: list[int]) -> tuple[list[tuple[int, int]], list[int]]:
    coeffs = [secret_byte & 0xFF] + [c & 0xFF for c in rand_coeffs]
    assert len(coeffs) == k
    shares = []
    for i in range(1, n + 1):
        x = i & 0xFF
        y = poly_eval(coeffs, x)
        shares.append((x, y))
    return shares, coeffs


def hmac_blake3(key: bytes, data: bytes) -> bytes:
    block_size = 64
    if len(key) > block_size:
        key = blake3.blake3(key).digest(32)
    key = key + b"\x00" * (block_size - len(key))
    ipad = bytes(x ^ 0x36 for x in key)
    opad = bytes(x ^ 0x5C for x in key)
    inner = blake3.blake3(ipad + data).digest(32)
    return blake3.blake3(opad + inner).digest(32)


def hkdf_blake3(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    prk = hmac_blake3(salt, ikm)
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_blake3(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def hex_spaced(b: bytes, group: int = 4) -> str:
    h = b.hex()
    return " ".join(h[i : i + group] for i in range(0, len(h), group))


def write_sss(root: Path) -> None:
    lines: list[str] = []
    lines.append("# CESS v0.2 — Shamir Secret Sharing over GF(2^8), field polynomial x^8+x^4+x^3+x+1 (0x11B)")
    lines.append('schema = "cess-sss-v0.2"')
    lines.append("")

    def add_vec(
        desc: str,
        secret: int,
        k: int,
        n: int,
        coeffs: list[int],
        recover_from: list[list[int]],
        rejection_cases: list[dict] | None = None,
    ):
        lines.append("[[vectors]]")
        lines.append(f'description = "{desc}"')
        lines.append(f"secret_byte = 0x{secret:02x}")
        lines.append(f"threshold = {k}")
        lines.append(f"n_shares = {n}")
        lines.append("coefficients = [" + ", ".join(f"0x{c:02x}" for c in coeffs) + "]")
        sh, _ = shamir_split(secret, k, n, coeffs[1:k])
        lines.append("shares = [")
        for x, y in sh:
            lines.append(f'  {{ x = 0x{x:02x}, y = 0x{y:02x} }},')
        lines.append("]")
        lines.append("recover_from = [")
        for combo in recover_from:
            lines.append("  [" + ", ".join(str(i) for i in combo) + "],")
        lines.append("]")
        if rejection_cases:
            lines.append("rejection_cases = [")
            for r in rejection_cases:
                parts = []
                for kk, vv in r.items():
                    if isinstance(vv, str):
                        parts.append(f'{kk} = "{vv}"')
                    else:
                        parts.append(f"{kk} = {vv}")
                lines.append("  { " + ", ".join(parts) + " },")
            lines.append("]")
        lines.append("")

    add_vec(
        "2-of-3 sharing with secret 0x42 and linear term 0xAB",
        0x42,
        2,
        3,
        [0x42, 0xAB],
        [[0, 1], [0, 2], [1, 2]],
    )
    add_vec(
        "3-of-5 sharing with secret 0x11 and quadratic polynomial",
        0x11,
        3,
        5,
        [0x11, 0x33, 0x55],
        [[0, 1, 2], [1, 3, 4], [0, 2, 4]],
    )
    combos_3_6 = []
    for a in range(6):
        for b in range(a + 1, 6):
            for c in range(b + 1, 6):
                combos_3_6.append([a, b, c])
    add_vec(
        "3-of-6 all C(6,3)=20 recovery combinations (share indices 0..5 map to x=1..6)",
        0x77,
        3,
        6,
        [0x77, 0x01, 0x02],
        combos_3_6,
    )
    add_vec(
        "k-of-k (3-of-3) minimal quorum",
        0xAA,
        3,
        3,
        [0xAA, 0xBB, 0xCC],
        [[0, 1, 2]],
    )
    add_vec(
        "1-of-5 degenerate case: constant polynomial, all y equal secret",
        0x5A,
        1,
        5,
        [0x5A],
        [[0], [1], [4]],
    )
    add_vec(
        "all-zero secret byte",
        0x00,
        2,
        4,
        [0x00, 0x3C],
        [[0, 1], [2, 3]],
    )
    add_vec(
        "all-0xFF secret byte",
        0xFF,
        2,
        4,
        [0xFF, 0x01],
        [[0, 3]],
    )
    # n=255, k=2: include subset of shares
    k, n = 2, 255
    coeffs_max = [0x01, 0x02]
    sh, _ = shamir_split(0x99, k, n, coeffs_max[: k - 1])
    lines.append("[[vectors]]")
    lines.append(
        'description = "maximum n=255 with k=2: first four shares, last share, and reconstruction from indices 0 and 254"'
    )
    lines.append("secret_byte = 0x99")
    lines.append("threshold = 2")
    lines.append("n_shares = 255")
    lines.append("coefficients = [0x99, 0x01]")
    lines.append("shares_sample = [")
    for i in [0, 1, 2, 253, 254]:
        x, y = sh[i]
        lines.append(f'  {{ index = {i}, x = 0x{x:02x}, y = 0x{y:02x} }},')
    lines.append("]")
    lines.append("recover_from = [[0, 254]]")
    lines.append("")
    lines.append("[[vectors]]")
    lines.append('description = "reconstruction with duplicate x index must fail (duplicate share index)"')
    lines.append('expected_error = "DUPLICATE_SHARE_INDEX"')
    lines.append("")
    lines.append("[[vectors]]")
    lines.append('description = "integrity failure when share y does not match polynomial"')
    lines.append('expected_error = "INTEGRITY_FAILURE"')
    lines.append("")

    (root / "sss.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote sss.toml", file=sys.stderr)


def write_blake3(root: Path) -> None:
    lines = [
        '# CESS v0.2 — BLAKE3 digest and keyed MAC',
        'schema = "cess-blake3-v0.2"',
        "",
    ]

    def add(desc: str, data: bytes, key: bytes | None = None):
        lines.append("[[vectors]]")
        lines.append(f'description = "{desc}"')
        lines.append(f"byte_length = {len(data)}")
        lines.append(f'input_hex = "{data.hex()}"')
        if key is None:
            d = blake3.blake3(data).digest(32)
        else:
            lines.append(f'key_hex = "{key.hex()}"')
            d = blake3.blake3(data, key=key).digest(32)
        lines.append(f'blake3_digest_hex = "{d.hex()}"')
        lines.append("")

    add("empty input", b"")
    add("single byte 0x00", b"\x00")
    z4 = b"\x00" * (4 * 1024 * 1024)
    add("4 MiB all-zero block", z4)
    rnd = hashlib.sha256(b"cess-blake3-prng").digest() * (4 * 1024 * 1024 // 32 + 1)
    rnd = rnd[: 4 * 1024 * 1024]
    add("4 MiB deterministic pseudorandom block (SHA-256 expansion, informative only)", rnd)
    k32 = hashlib.sha256(b"cess-blake3-keyed").digest()
    add("keyed BLAKE3 MAC key 32 bytes, message test vector", b"cess-keyed-msg", k32)
    flip = bytearray(b"fixed message for bit flip")
    flip[3] ^= 1
    add("bit-flip detection: one bit changed in message", bytes(flip))

    (root / "blake3.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote blake3.toml", file=sys.stderr)


def write_argon2id(root: Path) -> None:
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )
    lines = [
        "# CESS v0.2 — Argon2id per RFC 9106 at CESS profile",
        "# memory_kib = 65536, iterations = 3, parallelism = 4, salt = 16 bytes, output = 32 bytes",
        'schema = "cess-argon2id-v0.2"',
        "",
    ]

    def add_case(desc: str, pin: str, salt: bytes, reject: bool = False, err: str | None = None):
        lines.append("[[vectors]]")
        lines.append(f'description = "{desc}"')
        lines.append(f'pin = "{pin}"')
        lines.append(f'salt_hex = "{salt.hex()}"')
        lines.append("memory_kib = 65536")
        lines.append("iterations = 3")
        lines.append("parallelism = 4")
        lines.append("output_length = 32")
        if reject:
            lines.append(f'expected_error = "{err}"')
        else:
            h = argon2.low_level.hash_secret_raw(
                pin.encode("utf-8"),
                salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=argon2.low_level.Type.ID,
            )
            lines.append(f'argon2id_output_hex = "{h.hex()}"')
        lines.append("")

    salt1 = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    add_case("standard PIN at CESS parameters", "correct horse battery staple", salt1)
    salt2 = bytes.fromhex("1112131415161718191a1b1c1d1e1f20")
    add_case("5-character PIN boundary", "abcde", salt2)
    salt3 = bytes.fromhex("2122232425262728292a2b2c2d2e2f30")
    add_case("all-numeric PIN", "12345678", salt3)
    salt4 = bytes.fromhex("3132333435363738393a3b3c3d3e3f40")
    add_case("all-alpha PIN", "AlphaBeta", salt4)
    salt5 = bytes.fromhex("4142434445464748494a4b4c4d4e4f50")
    add_case("mixed-case alphanumeric PIN", "CeSs2026x", salt5)
    lines.append("[[rejection_cases]]")
    lines.append('description = "PIN shorter than 5 characters"')
    lines.append('pin = "1234"')
    lines.append('expected_error = "PIN_TOO_SHORT"')
    lines.append("")
    lines.append("[[rejection_cases]]")
    lines.append('description = "empty PIN"')
    lines.append('pin = ""')
    lines.append('expected_error = "PIN_EMPTY"')
    lines.append("")

    (root / "argon2id.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote argon2id.toml", file=sys.stderr)


def write_hkdf(root: Path) -> None:
    lines = [
        "# CESS v0.2 — HKDF-BLAKE3 (RFC 5869 structure, HMAC-BLAKE3 as PRF)",
        'schema = "cess-hkdf-blake3-v0.2"',
        "",
    ]

    def add(desc: str, ikm: bytes, salt: bytes, info: bytes, out_len: int):
        lines.append("[[vectors]]")
        lines.append(f'description = "{desc}"')
        lines.append(f'ikm_hex = "{ikm.hex()}"')
        lines.append(f'salt_hex = "{salt.hex()}"')
        lines.append(f'info_utf8 = "{info.decode("utf-8")}"')
        lines.append(f"output_length = {out_len}")
        okm = hkdf_blake3(ikm, salt, info, out_len)
        lines.append(f'okm_hex = "{okm.hex()}"')
        lines.append("")

    ecdh_shared = hashlib.sha256(b"classical-ecdh-shared").digest()
    add("classical-only ECDH shared secret expanded to session key", ecdh_shared, b"", b"cess-kem-v1", 32)
    add("classical-only with explicit salt", ecdh_shared, b"\x00" * 32, b"cess-kem-v1", 32)
    pq = hashlib.sha256(b"pq-kem-shared").digest()
    hybrid = ecdh_shared + pq
    add("hybrid classical || PQ combiner input", hybrid, b"", b"cess-kem-v1", 32)
    pin_ikm = hashlib.sha256(b"argon2id-output").digest()
    add("PIN wrap KDF info cess-pin-v1", pin_ikm, b"", b"cess-pin-v1", 32)
    add("64-byte expanded output", ecdh_shared, b"", b"cess-kem-v1", 64)

    (root / "hkdf_blake3.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote hkdf_blake3.toml", file=sys.stderr)


def write_ecdh_brainpool(root: Path) -> None:
    lines = [
        "# CESS v0.2 — Brainpool ECDH (RFC 5639, BSI TR-03111 practices)",
        'schema = "cess-ecdh-brainpool-v0.2"',
        "",
    ]
    # Fixed private scalars (small integers valid on both curves for static test)
    priv_a384 = ec.derive_private_key(0x10001, ec.BrainpoolP384R1())
    priv_b384 = ec.derive_private_key(0x20002, ec.BrainpoolP384R1())
    pub_a384 = priv_a384.public_key()
    pub_b384 = priv_b384.public_key()
    shared384 = priv_a384.exchange(ec.ECDH(), pub_b384)
    lines.append("[[vectors]]")
    lines.append('description = "BrainpoolP384r1 static ECDH between fixed test scalars"')
    lines.append(f'private_a_hex = "{priv_a384.private_numbers().private_value:096x}"')
    lines.append(f'private_b_hex = "{priv_b384.private_numbers().private_value:096x}"')
    lines.append(f'shared_secret_hex = "{shared384.hex()}"')
    lines.append("")

    priv_a512 = ec.derive_private_key(0x10001, ec.BrainpoolP512R1())
    priv_b512 = ec.derive_private_key(0x20002, ec.BrainpoolP512R1())
    shared512 = priv_a512.exchange(ec.ECDH(), priv_b512.public_key())
    lines.append("[[vectors]]")
    lines.append('description = "BrainpoolP512r1 static ECDH between fixed test scalars"')
    lines.append(f'private_a_hex = "{priv_a512.private_numbers().private_value:0128x}"')
    lines.append(f'private_b_hex = "{priv_b512.private_numbers().private_value:0128x}"')
    lines.append(f'shared_secret_hex = "{shared512.hex()}"')
    lines.append("")

    lines.append("[[rejection_cases]]")
    lines.append('description = "cross-curve ECDH: P384 private with P512 peer public must be rejected"')
    lines.append('operation = "ecdh"')
    lines.append('expected_error = "CROSS_CURVE_REJECTED"')
    lines.append("")

    lines.append("[[rejection_cases]]")
    lines.append('description = "invalid encoding: point at infinity (implementation must reject)"')
    lines.append('operation = "ecdh"')
    lines.append('expected_error = "INVALID_EC_POINT"')
    lines.append("")

    lines.append("[[rejection_cases]]")
    lines.append('description = "coordinates not on curve (random bytes as public key)"')
    lines.append('operation = "ecdh"')
    lines.append('expected_error = "INVALID_EC_POINT"')
    lines.append("")

    (root / "ecdh_brainpool.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote ecdh_brainpool.toml", file=sys.stderr)


def write_bulk_aead(root: Path) -> None:
    key32 = hashlib.sha256(b"cess-chacha-key").digest()
    nonce12 = b"\x00" * 12
    pt = b"CESS bulk AEAD plaintext vector."
    aad = b"cess-aad-v1"
    aad_alt = b"cess-aad-alt"

    def chacha_poly(ptb: bytes, aadb: bytes, nonce: bytes):
        return ChaCha20Poly1305(key32).encrypt(nonce, ptb, aadb)

    ct_std = chacha_poly(pt, aad, nonce12)
    ct_empty = chacha_poly(b"", aad, nonce12)
    ct_aad = chacha_poly(pt, aad_alt, nonce12)

    serpent_key = hashlib.sha256(b"cess-serpent-key").digest()
    iv16 = hashlib.sha256(b"cess-serpent-iv").digest()[:16]
    ct_serp = serpent_ctr_bytes(serpent_key, iv16, pt)
    poly_key = hashlib.sha256(b"cess-poly1305-from-session").digest()
    tag_serp = poly1305_tag_rfc8439(poly_key, aad, ct_serp)

    inner = chacha_poly(pt, aad, nonce12)
    outer_ct = serpent_ctr_bytes(serpent_key, iv16, inner)
    tag_cascade = poly1305_tag_rfc8439(poly_key, aad, outer_ct)

    large_pt = b"\x5a" * 4096
    ct_large = chacha_poly(large_pt, aad, nonce12)

    lines = [
        "# CESS v0.2 — ChaCha20-Poly1305 (RFC 8439), Serpent-256-CTR + Poly1305, cascade",
        "# Serpent-CTR from scripts/serpent_helper; Poly1305 MAC per RFC 8439 padding on aad||ciphertext",
        'schema = "cess-bulk-aead-v0.2"',
        "",
        "[[vectors]]",
        'description = "ChaCha20-Poly1305 standard message with AAD"',
        f'key_hex = "{key32.hex()}"',
        f'nonce_hex = "{nonce12.hex()}"',
        f'aad_hex = "{aad.hex()}"',
        f'plaintext_hex = "{pt.hex()}"',
        f'ciphertext_hex = "{ct_std.hex()}"',
        "",
        "[[vectors]]",
        'description = "ChaCha20-Poly1305 empty plaintext"',
        f'key_hex = "{key32.hex()}"',
        f'nonce_hex = "{nonce12.hex()}"',
        f'aad_hex = "{aad.hex()}"',
        'plaintext_hex = ""',
        f'ciphertext_hex = "{ct_empty.hex()}"',
        "",
        "[[vectors]]",
        'description = "ChaCha20-Poly1305 AAD variation"',
        f'key_hex = "{key32.hex()}"',
        f'nonce_hex = "{nonce12.hex()}"',
        f'aad_hex = "{aad_alt.hex()}"',
        f'plaintext_hex = "{pt.hex()}"',
        f'ciphertext_hex = "{ct_aad.hex()}"',
        "",
        "[[vectors]]",
        'description = "ChaCha20-Poly1305 4096-byte plaintext (large message sample)"',
        f'key_hex = "{key32.hex()}"',
        f'nonce_hex = "{nonce12.hex()}"',
        f'aad_hex = "{aad.hex()}"',
        f'plaintext_length = {len(large_pt)}',
        f'plaintext_blake3_hex = "{blake3.blake3(large_pt).digest(32).hex()}"',
        f'ciphertext_hex = "{ct_large.hex()}"',
        "",
        "[[vectors]]",
        'description = "Serpent-256-CTR ciphertext with Poly1305 tag (separate poly1305 key)"',
        f'serpent_key_hex = "{serpent_key.hex()}"',
        f'ctr_iv_hex = "{iv16.hex()}"',
        f'aad_hex = "{aad.hex()}"',
        f'plaintext_hex = "{pt.hex()}"',
        f'ciphertext_hex = "{ct_serp.hex()}"',
        f'poly1305_key_hex = "{poly_key.hex()}"',
        f'tag_hex = "{tag_serp.hex()}"',
        "",
        "[[vectors]]",
        'description = "Cascade: ChaCha20-Poly1305 then Serpent-CTR; Poly1305 on outer"',
        f'chacha_key_hex = "{key32.hex()}"',
        f'chacha_nonce_hex = "{nonce12.hex()}"',
        f'serpent_key_hex = "{serpent_key.hex()}"',
        f'ctr_iv_hex = "{iv16.hex()}"',
        f'aad_hex = "{aad.hex()}"',
        f'plaintext_hex = "{pt.hex()}"',
        f'inner_ciphertext_hex = "{inner.hex()}"',
        f'outer_ciphertext_hex = "{outer_ct.hex()}"',
        f'poly1305_key_hex = "{poly_key.hex()}"',
        f'outer_tag_hex = "{tag_cascade.hex()}"',
        "",
        "[[rejection_cases]]",
        'description = "wrong key for ChaCha20-Poly1305"',
        'expected_error = "AUTH_FAILED"',
        "",
        "[[rejection_cases]]",
        'description = "truncated ciphertext"',
        'expected_error = "AUTH_FAILED"',
        "",
        "[[rejection_cases]]",
        'description = "bit-flipped AEAD tag"',
        'expected_error = "AUTH_FAILED"',
        "",
        "[[rejection_cases]]",
        'description = "wrong nonce (must not decrypt)"',
        'expected_error = "AUTH_FAILED"',
        "",
    ]

    (root / "bulk_aead.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote bulk_aead.toml", file=sys.stderr)


def write_pin_wrap(root: Path) -> None:
    salt = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    pin_ok = "correct horse battery staple"
    raw = argon2.low_level.hash_secret_raw(
        pin_ok.encode(),
        salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )
    wrap_key = hkdf_blake3(raw, b"", b"cess-pin-v1", 32)
    share_plain = bytes([0x42, 0x11, 0x99])
    nonce = b"\x01" * 12
    c = ChaCha20Poly1305(wrap_key)
    wrapped = c.encrypt(nonce, share_plain, b"cess-pin-wrap")
    iv_serp = hashlib.sha256(b"pin-wrap-serpent-iv").digest()[:16]
    wrapped_serp = serpent_ctr_bytes(wrap_key, iv_serp, share_plain)
    lines = [
        "# CESS v0.2 — PIN wrap: Argon2id -> HKDF-BLAKE3 -> AEAD",
        'schema = "cess-pin-wrap-v0.2"',
        "",
        "[[vectors]]",
        'description = "Argon2id to HKDF-BLAKE3 to ChaCha20-Poly1305 wrap of 3-byte share"',
        f'pin = "{pin_ok}"',
        f'salt_hex = "{salt.hex()}"',
        f'argon2id_output_hex = "{raw.hex()}"',
        f'wrap_key_hex = "{wrap_key.hex()}"',
        f'nonce_hex = "{nonce.hex()}"',
        f'share_plain_hex = "{share_plain.hex()}"',
        f'wrapped_share_hex = "{wrapped.hex()}"',
        "",
        "[[vectors]]",
        'description = "Same HKDF-BLAKE3 key (cess-pin-v1) with Serpent-256-CTR wrap of same 3-byte share"',
        f'pin = "{pin_ok}"',
        f'salt_hex = "{salt.hex()}"',
        f'argon2id_output_hex = "{raw.hex()}"',
        f'wrap_key_hex = "{wrap_key.hex()}"',
        f'ctr_iv_hex = "{iv_serp.hex()}"',
        f'share_plain_hex = "{share_plain.hex()}"',
        f'wrapped_share_hex = "{wrapped_serp.hex()}"',
        "",
        "[[rejection_cases]]",
        'description = "wrong PIN yields AUTH_FAILED and no partial plaintext"',
        'expected_error = "AUTH_FAILED"',
        "",
        "[[rejection_cases]]",
        'description = "bit-flipped wrapped share ciphertext"',
        'expected_error = "AUTH_FAILED"',
        "",
    ]
    (root / "pin_wrap.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote pin_wrap.toml", file=sys.stderr)


def write_reed_solomon(root: Path) -> None:
    # RS as polynomial evaluation: 3 data bytes -> 6 symbols at x=1..6
    data = [0x10, 0x20, 0x30]
    shards = [poly_eval(data, x) for x in range(1, 7)]
    lines = [
        "# CESS v0.2 — Reed-Solomon style erasure shards (GF(2^8) evaluation at x=1..6, k=3)",
        'schema = "cess-rs-v0.2"',
        "",
        "[[vectors]]",
        'description = "3-of-6 erasure: six single-byte shards from degree-2 message polynomial"',
        f'data_bytes_hex = "{bytes(data).hex()}"',
        "shards_hex = [",
    ]
    for i, s in enumerate(shards):
        b = bytes([s])
        lines.append(f'  {{ index = {i}, shard_hex = "{b.hex()}", blake3 = "{blake3.blake3(b).digest(32).hex()}" }},')
    lines.append("]")
    combos = []
    for a in range(6):
        for b in range(a + 1, 6):
            for c in range(b + 1, 6):
                combos.append([a, b, c])
    lines.append("recover_from = [")
    for combo in combos:
        lines.append("  " + str(combo) + ",")
    lines.append("]")
    lines.append("")
    # 2-of-4: four shards from degree-1 polynomial over 4 points
    data2 = [0x55, 0x66]
    shards2 = [poly_eval(data2, x) for x in range(1, 5)]
    combos2 = [[a, b] for a in range(4) for b in range(a + 1, 4)]
    lines.append("[[vectors]]")
    lines.append('description = "2-of-4 erasure shards (linear polynomial)"')
    lines.append(f'data_bytes_hex = "{bytes(data2).hex()}"')
    lines.append("shards_hex = [")
    for i, s in enumerate(shards2):
        b = bytes([s])
        lines.append(f'  {{ index = {i}, shard_hex = "{b.hex()}", blake3 = "{blake3.blake3(b).digest(32).hex()}" }},')
    lines.append("]")
    lines.append("recover_from = [")
    for combo in combos2:
        lines.append("  " + str(combo) + ",")
    lines.append("]")
    lines.append("")
    # k-of-k on 3 points
    data3 = [0xDE, 0xAD, 0xBE]
    sh3 = [poly_eval(data3, x) for x in range(1, 4)]
    lines.append("[[vectors]]")
    lines.append('description = "k-of-k (3-of-3) all shards required"')
    lines.append(f'data_bytes_hex = "{bytes(data3).hex()}"')
    lines.append("shards_hex = [")
    for i, s in enumerate(sh3):
        b = bytes([s])
        lines.append(f'  {{ index = {i}, shard_hex = "{b.hex()}", blake3 = "{blake3.blake3(b).digest(32).hex()}" }},')
    lines.append("]")
    lines.append("recover_from = [[0, 1, 2]]")
    lines.append("")
    lines.append("[[rejection_cases]]")
    lines.append('description = "k-1 shards present: cannot recover data"')
    lines.append('expected_error = "INSUFFICIENT_SHARDS"')
    lines.append("")

    (root / "reed_solomon.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote reed_solomon.toml", file=sys.stderr)


def write_rejection(root: Path) -> None:
    lines = [
        "# CESS v0.2 — Negative tests (expected_error vocabulary matches spec section 14)",
        'schema = "cess-rejection-v0.2"',
        "",
        "[[vectors]]",
        'description = "wrong PIN unwrap"',
        'operation = "pin_unwrap"',
        'expected_error = "AUTH_FAILED"',
        "",
        "[[vectors]]",
        'description = "duplicate share index in envelope"',
        'operation = "share_import"',
        'expected_error = "DUPLICATE_SHARE_INDEX"',
        "",
        "[[vectors]]",
        'description = "insufficient shares for threshold"',
        'operation = "sss_reconstruct"',
        'expected_error = "INSUFFICIENT_SHARES"',
        "",
        "[[vectors]]",
        'description = "corrupted erasure shard"',
        'operation = "rs_decode"',
        'expected_error = "INTEGRITY_FAILURE"',
        "",
        "[[vectors]]",
        'description = "PIN too short"',
        'operation = "pin_enroll"',
        'expected_error = "PIN_TOO_SHORT"',
        "",
        "[[vectors]]",
        'description = "invalid uncompressed EC point"',
        'operation = "ecdh"',
        'expected_error = "INVALID_EC_POINT"',
        "",
        "[[vectors]]",
        'description = "nonce reuse attempt"',
        'operation = "aead_encrypt"',
        'expected_error = "NONCE_REUSE"',
        "",
        "[[vectors]]",
        'description = "cross-curve KEM"',
        'operation = "ecdh"',
        'expected_error = "CROSS_CURVE_REJECTED"',
        "",
        "[[vectors]]",
        'description = "tampered share metadata"',
        'operation = "share_verify"',
        'expected_error = "INTEGRITY_FAILURE"',
        "",
    ]
    (root / "rejection.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote rejection.toml", file=sys.stderr)


def write_integration(root: Path) -> None:
    # Fixed 1 MiB patterns using deterministic expansion
    def mib_zeros():
        return b"\x00" * (1024 * 1024)

    def mib_ff():
        return b"\xff" * (1024 * 1024)

    def mib_prng():
        h = hashlib.sha256(b"cess-integration-prng-seed").digest()
        out = bytearray()
        while len(out) < 1024 * 1024:
            h = hashlib.sha256(h).digest()
            out.extend(h)
        return bytes(out[: 1024 * 1024])

    def pipeline(name: str, data: bytes, k: int, n: int, coeffs: list[int], use_cascade: bool):
        src_hash = blake3.blake3(data).digest(32)
        sess = hkdf_blake3(hashlib.sha256(name.encode()).digest(), b"", b"cess-kem-v1", 32)
        key32 = sess
        nonce12 = hashlib.sha256((name + "nonce").encode()).digest()[:12]
        aad = b"cess-integration"
        if use_cascade:
            inner = ChaCha20Poly1305(key32).encrypt(nonce12, data, aad)
            sk2 = hashlib.sha256(key32 + b"serpent").digest()
            iv16 = hashlib.sha256((name + "iv").encode()).digest()[:16]
            enc = serpent_ctr_bytes(sk2, iv16, inner)
        else:
            enc = ChaCha20Poly1305(key32).encrypt(nonce12, data, aad)
        enc_hash = blake3.blake3(enc).digest(32)
        # SSS on a 32-byte synthetic secret derived from data hash for vector linkage
        secret_byte = src_hash[0]
        sh, _ = shamir_split(secret_byte, k, n, [src_hash[i] for i in range(1, k)])
        shard_hashes = [blake3.blake3(bytes([y])).digest(32).hex() for _, y in sh]
        wrapped = []
        salt = hashlib.sha256((name + "salt").encode()).digest()[:16]
        pin = "integration-test-pin-ok"
        raw = argon2.low_level.hash_secret_raw(
            pin.encode(),
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=argon2.low_level.Type.ID,
        )
        wk = hkdf_blake3(raw, b"", b"cess-pin-v1", 32)
        for i, (_, y) in enumerate(sh):
            nnc = hashlib.sha256(f"{name}-{i}".encode()).digest()[:12]
            ct = ChaCha20Poly1305(wk).encrypt(nnc, bytes([y]), b"wrap")
            wrapped.append(ct.hex())
        return {
            "name": name,
            "source_blake3": src_hash.hex(),
            "session_key_hex": sess.hex(),
            "encrypted_blob_blake3": enc_hash.hex(),
            "sss_threshold": k,
            "sss_n": n,
            "share_y_blake3_hashes": shard_hashes,
            "wrapped_shares_hex": wrapped,
            "cascade": use_cascade,
        }

    p1 = pipeline("vec-2of3-chacha-zero", mib_zeros(), 2, 3, [0, 0], False)
    p2 = pipeline("vec-3of5-serpent-cascade-ff", mib_ff(), 3, 5, [0, 0, 0], True)
    p3 = pipeline("vec-3of6-chacha-prng", mib_prng(), 3, 6, [0, 0, 0], False)

    lines = [
        "# CESS v0.2 — End-to-end integration (hashes; 1 MiB payloads not inlined)",
        'schema = "cess-integration-v0.2"',
        "",
        "[[vectors]]",
        f'description = "2-of-3, ChaCha20-Poly1305, 1 MiB all-zero payload"',
        f'source_payload = "1 MiB all-zero"',
        f'source_blake3_hex = "{p1["source_blake3"]}"',
        f'session_key_hex = "{p1["session_key_hex"]}"',
        f'encrypted_blob_blake3_hex = "{p1["encrypted_blob_blake3"]}"',
        f'threshold = {p1["sss_threshold"]}',
        f'n_shares = {p1["sss_n"]}',
        f'share_y_blake3_hashes = {p1["share_y_blake3_hashes"]}',
        f'wrapped_shares_hex = {p1["wrapped_shares_hex"]}',
        "",
        "[[vectors]]",
        f'description = "3-of-5, Serpent cascade option, 1 MiB all-0xFF payload"',
        f'source_payload = "1 MiB all-0xFF"',
        f'source_blake3_hex = "{p2["source_blake3"]}"',
        f'session_key_hex = "{p2["session_key_hex"]}"',
        f'encrypted_blob_blake3_hex = "{p2["encrypted_blob_blake3"]}"',
        f'threshold = {p2["sss_threshold"]}',
        f'n_shares = {p2["sss_n"]}',
        f'cascade = true',
        f'share_y_blake3_hashes = {p2["share_y_blake3_hashes"]}',
        f'wrapped_shares_hex = {p2["wrapped_shares_hex"]}',
        "",
        "[[vectors]]",
        f'description = "3-of-6, ChaCha20-Poly1305, 1 MiB PRNG payload"',
        f'source_payload = "1 MiB SHA-256 chain (informative PRNG only)"',
        f'source_blake3_hex = "{p3["source_blake3"]}"',
        f'session_key_hex = "{p3["session_key_hex"]}"',
        f'encrypted_blob_blake3_hex = "{p3["encrypted_blob_blake3"]}"',
        f'threshold = {p3["sss_threshold"]}',
        f'n_shares = {p3["sss_n"]}',
        f'share_y_blake3_hashes = {p3["share_y_blake3_hashes"]}',
        f'wrapped_shares_hex = {p3["wrapped_shares_hex"]}',
        "",
    ]
    (root / "integration.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote integration.toml", file=sys.stderr)


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "vectors"
    root.mkdir(parents=True, exist_ok=True)
    write_sss(root)
    write_blake3(root)
    write_argon2id(root)
    write_hkdf(root)
    write_ecdh_brainpool(root)
    try:
        write_bulk_aead(root)
    except Exception as e:
        print("bulk_aead error:", e, file=sys.stderr)
        raise
    write_pin_wrap(root)
    write_reed_solomon(root)
    write_rejection(root)
    write_integration(root)
    print("done", file=sys.stderr)


if __name__ == "__main__":
    main()
