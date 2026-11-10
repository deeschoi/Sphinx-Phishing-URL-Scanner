#!/bin/sh
# Build a production Vercel output.
#
# Dependencies are installed by vercel.json's installCommand
# (`pip install -r requirements-serve.txt`). That set is about 330 MB
# unzipped. A custom install command disables Vercel's automatic packing
# and the builder then refuses anything over 225 MB unless
# VERCEL_SUPPORT_LARGE_FUNCTIONS=1. Large functions allow up to 5 GB.
# Keep the install command: pyproject.toml still depends on
# requirements.txt, and that file pulls in the NCCL wheel.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

# Pass --token explicitly so a missing GitHub secret fails here. CLI 48.12.1
# also rejected `functions.app.py` (it only matches files in `api/`); the
# workflow installs 65.14.0, which accepts the FastAPI entrypoint.
if [ -z "${VERCEL_TOKEN:-}" ]; then
  echo "VERCEL_TOKEN is empty. Add it under GitHub Settings → Environments → production → Environment secrets." >&2
  exit 1
fi

# CLI 65 installs the Python runtime with uv. A missing binary fails the
# build as `[UV_ERROR] uv is required but was not found in PATH`.
if ! command -v uv >/dev/null 2>&1; then
  echo "uv is not on PATH. The Deploy Vercel workflow installs it with astral-sh/setup-uv; locally, install uv before vercel build." >&2
  exit 1
fi

vercel pull --yes --environment=production --token "$VERCEL_TOKEN"

# Must be set in this process. `vercel build` reads it from the environment;
# a Vercel project variable is not required for the size check.
export VERCEL_SUPPORT_LARGE_FUNCTIONS=1
vercel build --prod --token "$VERCEL_TOKEN"
python scripts/check_function_bundle.py
