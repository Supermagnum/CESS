"""Shared ECDH verification for Brainpool JSON corpora (RFC 6932, RFC 7027, etc.).

Shared secret is the x-coordinate of the agreed point (SEC1 field element octet string),
matching TLS pre-master secret encoding in RFC 7027 Appendix A.

brainpoolP224r1: OpenSSL CLI (cryptography does not expose this curve).
Other Brainpool curves in the JSON: cryptography ECDH.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec


def curve_named(name: str) -> ec.EllipticCurve:
    m = {
        "brainpoolP256r1": ec.BrainpoolP256R1,
        "brainpoolP384r1": ec.BrainpoolP384R1,
        "brainpoolP512r1": ec.BrainpoolP512R1,
    }
    if name not in m:
        raise KeyError(name)
    return m[name]()


def priv_from_hex(curve: ec.EllipticCurve, d_hex: str) -> ec.EllipticCurvePrivateKey:
    d = bytes.fromhex(d_hex)
    return ec.derive_private_key(int.from_bytes(d, "big"), curve)


def pub_from_hex(curve: ec.EllipticCurve, x_hex: str, y_hex: str) -> ec.EllipticCurvePublicKey:
    x = bytes.fromhex(x_hex)
    y = bytes.fromhex(y_hex)
    return ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"),
        y=int.from_bytes(y, "big"),
        curve=curve,
    ).public_key()


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    s = []
    while n:
        s.append(n & 0xFF)
        n >>= 8
    s.reverse()
    return bytes([0x80 | len(s)] + s)


def _der_seq(content: bytes) -> bytes:
    return b"\x30" + _der_len(len(content)) + content


def _der_bitstring(s: bytes) -> bytes:
    content = b"\x00" + s
    return b"\x03" + _der_len(len(content)) + content


def _der_ec_private_key_brainpool_p224(d: bytes) -> bytes:
    oid_curve = bytes.fromhex("06092b2403030208010105")
    body = b"\x02\x01\x01"
    body += b"\x04" + _der_len(len(d)) + d
    body += b"\xa0" + _der_len(len(oid_curve)) + oid_curve
    return _der_seq(body)


def _der_ec_pubkey_spki_brainpool_p224(x: bytes, y: bytes) -> bytes:
    oid_ec = bytes.fromhex("06072a8648ce3d0201")
    oid_curve = bytes.fromhex("06092b2403030208010105")
    alg_id = _der_seq(oid_ec + oid_curve)
    point = b"\x04" + x + y
    return _der_seq(alg_id + _der_bitstring(point))


def openssl_ecdh_p224(d_hex: str, x_peer_hex: str, y_peer_hex: str) -> bytes:
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl not found in PATH (required for brainpoolP224r1)")

    d = bytes.fromhex(d_hex)
    xb = bytes.fromhex(x_peer_hex)
    yb = bytes.fromhex(y_peer_hex)
    priv_der = _der_ec_private_key_brainpool_p224(d)
    pub_der = _der_ec_pubkey_spki_brainpool_p224(xb, yb)

    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        priv_der_path = p / "priv.der"
        pub_der_path = p / "peer_pub.der"
        priv_pem_path = p / "priv.pem"
        pub_pem_path = p / "peer.pem"
        out_path = p / "shared.bin"

        priv_der_path.write_bytes(priv_der)
        pub_der_path.write_bytes(pub_der)

        subprocess.run(
            ["openssl", "ec", "-inform", "DER", "-in", str(priv_der_path), "-out", str(priv_pem_path)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-pubin", "-inform", "DER", "-in", str(pub_der_path), "-out", str(pub_pem_path)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-derive",
                "-inkey",
                str(priv_pem_path),
                "-peerkey",
                str(pub_pem_path),
                "-out",
                str(out_path),
            ],
            check=True,
            capture_output=True,
        )
        return out_path.read_bytes()


def verify_ecdh_json(path: Path, ok_label: str) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    curves = data["curves"]
    for c in curves:
        cid = c["id"]
        if cid == "brainpoolP224r1":
            shared = openssl_ecdh_p224(c["dA"], c["x_qB"], c["y_qB"])
        else:
            crv = curve_named(cid)
            priv_a = priv_from_hex(crv, c["dA"])
            pub_b = pub_from_hex(crv, c["x_qB"], c["y_qB"])
            shared = priv_a.exchange(ec.ECDH(), pub_b)
        want_x = bytes.fromhex(c["x_Z"])
        if shared != want_x:
            print(
                f"FAIL {cid}: shared secret mismatch (got {len(shared)} bytes, want {len(want_x)})",
                file=sys.stderr,
            )
            return 1
    print(f"{ok_label} ({len(curves)} curves), file={path}")
    return 0
