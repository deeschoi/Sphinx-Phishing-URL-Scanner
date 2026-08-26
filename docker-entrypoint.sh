#!/bin/sh
# Compose mounts a named volume at /app/data as root. The app runs as
# scanner and SQLite cannot create scans.db on a root-owned directory.
# This script is root only long enough to fix that, then execs as scanner.
set -e
mkdir -p /app/data
if [ "$(id -u)" = "0" ]; then
  chown -R scanner:scanner /app/data
  exec gosu scanner "$@"
fi
exec "$@"
