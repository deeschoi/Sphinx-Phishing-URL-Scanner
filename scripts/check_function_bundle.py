#!/usr/bin/env python3
"""Fail the deploy before upload if the function cannot import its app.

With large functions on, the Vercel CLI keeps the wheels outside
``.vercel/output/functions/*.func`` and installs them from ``uv.lock``. A
``.func`` size check alone therefore says nothing about the dependencies:
a 1.2 MiB function with no wheels passed it, deployed, and crashed on import
with ``FUNCTION_INVOCATION_FAILED``. This script checks the inputs the
builder actually uses:

* no Install Command (in vercel.json or the pulled project settings), which
  would install into a local venv that is never shipped;
* ``uv.lock`` installs the project itself and the serve stack, and no NVIDIA
  or NCCL wheel;
* ``web/dist/index.html`` exists and ``vercel.json`` bundles it, so local
  runs and a missed promotion still serve the UI from the function;
* the build promoted the UI to the CDN (``.vercel/output/static`` holds
  ``index.html`` and at least one ``assets/*.js``). Without that, every page
  view waits on a cold Python function again (11-20 s measured);
* the ``.func`` directory is still under 500 MiB uncompressed.
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

LIMIT = 500 * 1024 * 1024
ROOT = Path(__file__).resolve().parent.parent
FUNCTIONS = ROOT / ".vercel" / "output" / "functions"
STATIC = ROOT / ".vercel" / "output" / "static"
PROJECT = ROOT / ".vercel" / "project.json"
REQUIRED = {"phishing", "fastapi", "xgboost-cpu", "numpy"}
FORBIDDEN_PREFIXES = ("nvidia-",)
# xgboost: the GPU build, which links libnccl. scikit-learn and pandas: the
# served model is native XGBoost, and xgboost imports both at start-up when
# they are installed, which slows every cold start.
FORBIDDEN_NAMES = {"xgboost", "scikit-learn", "pandas"}
FORBIDDEN_REASONS = {
    "xgboost": "pulls in the NCCL wheel",
    "scikit-learn": "is training-only and slows xgboost's import",
    "pandas": "is training-only and slows xgboost's import",
}


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def install_command_errors() -> list[str]:
    errors = []
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    if config.get("installCommand"):
        errors.append(
            "vercel.json sets installCommand. It installs into a local venv that "
            "large functions do not ship; let the builder install from uv.lock."
        )
    if PROJECT.is_file():
        settings = json.loads(PROJECT.read_text(encoding="utf-8")).get("settings") or {}
        if settings.get("installCommand"):
            errors.append(
                "The Vercel project has a saved Install Command "
                f"({settings['installCommand']!r}). Clear it under Project Settings "
                "→ Build and Deployment; it applies when vercel.json has none."
            )
    return errors


def frontend_errors() -> list[str]:
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    function = config.get("functions", {}).get("app.py", {})
    errors = []
    if "web/dist" not in function.get("includeFiles", ""):
        errors.append("vercel.json does not include web/dist in the function")
    if not (ROOT / "web" / "dist" / "index.html").is_file():
        errors.append("web/dist/index.html is missing: the build did not produce the UI")
    return errors


def static_output_errors() -> list[str]:
    """The UI must be in the CDN output, not only inside the function."""
    errors = []
    if not (STATIC / "index.html").is_file():
        errors.append(
            f"{STATIC.relative_to(ROOT)}/index.html is missing: the build did not "
            "promote web/dist to the CDN. Check VERCEL_FASTAPI_STATIC_CDN=1 in the "
            "build environment, app.frontend() in api/main.py, and "
            "[tool.vercel.fastapi.static] cdn = true in pyproject.toml."
        )
    if not any((STATIC / "assets").glob("*.js")):
        errors.append(f"{STATIC.relative_to(ROOT)}/assets has no .js bundle")
    return errors


def lock_errors() -> list[str]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    names = {package["name"] for package in lock.get("package", [])}
    errors = [
        f"uv.lock does not install {name}" for name in sorted(REQUIRED - names)
    ]
    for name in sorted(names):
        if name in FORBIDDEN_NAMES or name.startswith(FORBIDDEN_PREFIXES):
            reason = FORBIDDEN_REASONS.get(name, "pulls in the NCCL wheel")
            errors.append(f"uv.lock installs {name}, which {reason}")
    return errors


def function_errors() -> list[str]:
    funcs = sorted(path for path in FUNCTIONS.rglob("*.func") if path.is_dir())
    if not funcs:
        return [f"No .func directory under {FUNCTIONS}"]
    errors = []
    for func in funcs:
        size = directory_size(func)
        print(f"{func.relative_to(ROOT)}: {size / (1024 * 1024):.1f} MiB")
        if size > LIMIT:
            errors.append(
                f"{func.name} is over the {LIMIT // (1024 * 1024)} MiB uncompressed limit"
            )
    return errors


def main() -> int:
    errors = (
        install_command_errors()
        + lock_errors()
        + frontend_errors()
        + static_output_errors()
        + function_errors()
    )
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
