#!/bin/sh
# Turn on Vercel Deployment Protection for Preview deployments only.
#
# Production deployment URLs stay reachable. The smoke test and QStash both
# call the staged production URL before it is promoted, and QStash cannot
# present a dashboard login.
set -eu

if [ -z "${VERCEL_TOKEN:-}" ] || [ -z "${VERCEL_PROJECT_ID:-}" ]; then
  echo "VERCEL_TOKEN and VERCEL_PROJECT_ID are required" >&2
  exit 1
fi

query=""
if [ -n "${VERCEL_ORG_ID:-}" ]; then
  query="?teamId=${VERCEL_ORG_ID}"
fi

body=$(mktemp)
code=$(curl -sS -o "$body" -w "%{http_code}" \
  -X PATCH "https://api.vercel.com/v9/projects/${VERCEL_PROJECT_ID}${query}" \
  -H "Authorization: Bearer ${VERCEL_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"ssoProtection":{"deploymentType":"preview"}}')

if [ "$code" != "200" ]; then
  echo "Could not enable Preview Deployment Protection (HTTP ${code})" >&2
  python3 - "$body" <<'PY' >&2
import json
import sys

path = sys.argv[1]
try:
    payload = json.load(open(path, encoding="utf-8"))
except json.JSONDecodeError:
    print("response was not JSON")
    raise SystemExit(0)
error = payload.get("error") if isinstance(payload, dict) else payload
print(error if error is not None else "request failed")
PY
  rm -f "$body"
  exit 1
fi

rm -f "$body"
echo "Preview Deployment Protection is on."
