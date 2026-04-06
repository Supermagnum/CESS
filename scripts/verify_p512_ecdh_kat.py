#!/usr/bin/env python3
"""Verify BrainpoolP512r1 ECDH row in vectors/ecdh_p512_inner.toml (cryptography.ec)."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    path = root / "vectors" / "ecdh_p512_inner.toml"
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for row in data.get("vectors", []):
        if row.get("case_kind") != "ecdh_shared_secret":
            continue
        priv_hex = row["private_key_hex"]
        peer_hex = row["peer_public_key_hex"]
        expect_hex = row["expected_shared_secret_hex"]

        sk = ec.derive_private_key(int(priv_hex, 16), ec.BrainpoolP512R1())
        peer = bytes.fromhex(peer_hex)
        if peer[0] != 0x04 or len(peer) != 1 + 64 + 64:
            print("FAIL: peer_public_key_hex must be uncompressed SEC1 (04||x||y)", file=sys.stderr)
            return 1
        xb, yb = peer[1:65], peer[65:]
        pk = ec.EllipticCurvePublicNumbers(
            int.from_bytes(xb, "big"),
            int.from_bytes(yb, "big"),
            ec.BrainpoolP512R1(),
        ).public_key()
        shared = sk.exchange(ec.ECDH(), pk)
        got = shared.hex()
        if got != expect_hex:
            print(f"FAIL: shared secret mismatch\n got {got}\n exp {expect_hex}", file=sys.stderr)
            return 1
        print("OK: ecdh_p512_inner.toml ecdh_shared_secret matches cryptography BrainpoolP512r1")
        return 0
    print("FAIL: no ecdh_shared_secret row", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
