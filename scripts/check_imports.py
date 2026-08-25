#!/usr/bin/env python3
"""Import every module in the repo without running it.

The analysis scripts and the FastAPI app are thin wrappers over ``phishing``.
When a helper there is renamed, unit tests still pass because they exercise the
package directly, and the breakage only shows up when someone runs a script.
Executing each module's imports and module-level code (but not ``main``) is
enough to catch that.
"""

from __future__ import annotations

import importlib
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

PACKAGE_MODULES = [
    "phishing.cli",
    "phishing.config",
    "phishing.data",
    "phishing.decay",
    "phishing.evaluate",
    "phishing.explain",
    "phishing.fit",
    "phishing.io",
    "phishing.mining",
    "phishing.models",
    "phishing.scanner",
    "phishing.schema",
    "phishing.tuning",
    "phishing.features.extractor",
    "api.main",
]


def check_module(name: str) -> str | None:
    try:
        importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001 - report, do not abort the sweep
        return f"{type(exc).__name__}: {exc}"
    return None


def check_script(path: pathlib.Path) -> str | None:
    spec = importlib.util.spec_from_file_location(f"_check_{path.stem}", path)
    if spec is None or spec.loader is None:
        return "could not build an import spec"
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"
    if not callable(getattr(module, "main", None)):
        return "no main() entry point"
    return None


def main() -> int:
    sys.path.insert(0, str(ROOT))
    failures = []

    for name in PACKAGE_MODULES:
        error = check_module(name)
        print(f"{'ok  ' if error is None else 'FAIL'} {name}")
        if error:
            failures.append((name, error))

    for directory in (ROOT / "analysis", ROOT / "research" / "analysis"):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("[0-9]*.py")):
            error = check_script(path)
            rel = path.relative_to(ROOT)
            print(f"{'ok  ' if error is None else 'FAIL'} {rel}")
            if error:
                failures.append((str(rel), error))

    if failures:
        print(f"\n{len(failures)} module(s) failed to import:")
        for name, error in failures:
            print(f"  {name}: {error}")
        return 1

    print("\nAll entry points import cleanly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
