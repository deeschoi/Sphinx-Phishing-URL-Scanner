#!/usr/bin/env python3
"""Fail the deploy if the Python function is over Vercel's uncompressed limit.

The standard Python limit is 500 MB unzipped. Large Functions is a separate
opt-in and is not assumed here. After ``vercel build``, the function lives
under ``.vercel/output/functions/*.func``.
"""

from __future__ import annotations

import sys
from pathlib import Path

LIMIT = 500 * 1024 * 1024
ROOT = Path(__file__).resolve().parent.parent
FUNCTIONS = ROOT / ".vercel" / "output" / "functions"


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def main() -> int:
    funcs = sorted(path for path in FUNCTIONS.rglob("*.func") if path.is_dir())
    if not funcs:
        print(f"No .func directory under {FUNCTIONS}", file=sys.stderr)
        return 1
    failed = False
    for func in funcs:
        size = directory_size(func)
        print(f"{func.relative_to(ROOT)}: {size / (1024 * 1024):.1f} MiB")
        if size > LIMIT:
            failed = True
            print(
                f"  over the {LIMIT // (1024 * 1024)} MiB uncompressed limit",
                file=sys.stderr,
            )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
