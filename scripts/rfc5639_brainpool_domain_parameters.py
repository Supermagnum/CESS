#!/usr/bin/env python3
"""Check RFC 5639 brainpoolP*r1 domain parameters against OpenSSL explicit ecparam.

Compares prime field p and curve coefficient A to JSON. Requires openssl(1) in PATH.

Usage:
  .venv/bin/python scripts/rfc5639_brainpool_domain_parameters.py [json path]
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

OPENSSL_NAMES = {
    "brainpoolP256r1": "brainpoolP256r1",
    "brainpoolP384r1": "brainpoolP384r1",
    "brainpoolP512r1": "brainpoolP512r1",
}


def _parse_openssl_field(text: str, field: str) -> int | None:
    """Parse multi-line hex block after 'field:' (Prime, A, B) from openssl ecparam -text."""
    m = re.search(rf"^{field}:\s*\r?\n((?:[ \t]+[0-9a-f:]+\r?\n)+)", text, re.I | re.MULTILINE)
    if not m:
        return None
    hx = "".join(m.group(1).replace(":", "").split())
    return int(hx, 16)


def main() -> int:
    if shutil.which("openssl") is None:
        print("SKIP: openssl not in PATH", file=sys.stderr)
        return 0

    root = Path(__file__).resolve().parent.parent
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "testdata" / "rfc5639" / "rfc5639_brainpool_domain_parameters.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for c in data["curves"]:
        cid = c["id"]
        oname = OPENSSL_NAMES[cid]
        out = subprocess.run(
            ["openssl", "ecparam", "-param_enc", "explicit", "-name", oname, "-text", "-noout"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        p_int = _parse_openssl_field(out, "Prime")
        a_int = _parse_openssl_field(out, "A")
        if p_int is None or a_int is None:
            print(f"FAIL {cid}: could not parse openssl ecparam output", file=sys.stderr)
            return 1
        want_p = int(c["p_hex"], 16)
        want_a = int(c["a_hex"], 16)
        if p_int != want_p:
            print(f"FAIL {cid}: prime mismatch openssl vs JSON", file=sys.stderr)
            return 1
        if a_int != want_a:
            print(f"FAIL {cid}: curve coefficient A mismatch openssl vs JSON", file=sys.stderr)
            return 1
    print(f"OK: RFC 5639 domain parameters (openssl ecparam explicit), {len(data['curves'])} curves, file={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
