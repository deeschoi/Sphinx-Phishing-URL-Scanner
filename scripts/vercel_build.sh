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

vercel pull --yes --environment=production
vercel build --prod
python scripts/check_function_bundle.py
