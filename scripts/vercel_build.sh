#!/bin/sh
# Build a production Vercel output from the serve dependency set.
#
# Vercel installs requirements.txt. The function must see requirements-serve.txt
# (xgboost-cpu, no shap/numba). Swap for the build, then put the training file
# back so a failed run does not leave the checkout dirty.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

backup=$(mktemp)
cp requirements.txt "$backup"
restore() {
  cp "$backup" requirements.txt
  rm -f "$backup"
}
trap restore EXIT

cp requirements-serve.txt requirements.txt
vercel pull --yes --environment=production
vercel build --prod
python scripts/check_function_bundle.py
