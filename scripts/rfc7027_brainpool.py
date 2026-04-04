#!/usr/bin/env python3
"""Verify RFC 7027 Appendix A TLS Brainpool ECDH vectors (see brainpool_ecdh_common)."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from brainpool_ecdh_common import verify_ecdh_json


def main() -> int:
    default = Path(__file__).resolve().parent.parent / "testdata" / "rfc7027" / "rfc7027_brainpool_tls_ecdh.json"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    return verify_ecdh_json(path, "OK: RFC 7027 Appendix A TLS ECDH")


if __name__ == "__main__":
    raise SystemExit(main())
