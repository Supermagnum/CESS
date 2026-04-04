#!/usr/bin/env python3
"""Verify RFC 6932 Appendix A Brainpool ECDH vectors (see brainpool_ecdh_common)."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from brainpool_ecdh_common import verify_ecdh_json


def main() -> int:
    default = Path(__file__).resolve().parent.parent / "testdata" / "rfc6932" / "rfc6932_brainpool_ecdh.json"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    return verify_ecdh_json(path, "OK: RFC 6932 Appendix A ECDH")


if __name__ == "__main__":
    raise SystemExit(main())
