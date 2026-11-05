#!/bin/sh
# Build a production Vercel output.
#
# Dependencies come from uv.lock (the requirements-serve.txt set). Do not set
# an installCommand: Vercel then refuses to externalize a bundle over 225 MB.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

vercel pull --yes --environment=production
vercel build --prod
python scripts/check_function_bundle.py
