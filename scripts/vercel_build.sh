#!/bin/sh
# Build a production Vercel output.
#
# Dependencies come from uv.lock (the requirements-serve.txt set). The wheels
# are about 330 MB unzipped. vercel.json sets VERCEL_SUPPORT_LARGE_FUNCTIONS
# so a bundle over the 225 MB pack limit can still ship. Do not set an
# installCommand.
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

vercel pull --yes --environment=production --token "$VERCEL_TOKEN"
vercel build --prod --token "$VERCEL_TOKEN"
python scripts/check_function_bundle.py
