#!/bin/sh
# usage: compare-derived.sh COMMITTED REGENERATED
#
# Fails unless the two directories hold the same derived vector files with the
# same bytes, apart from the oracle's provenance `build` line: it names the
# target, the compiler and rustc of the machine that built the oracle.
set -eu

committed=$1
regenerated=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ "$(ls "$committed")" != "$(ls "$regenerated")" ]; then
  echo "the file names differ:" >&2
  ls "$committed" >&2
  echo "against" >&2
  ls "$regenerated" >&2
  exit 1
fi

status=0
for path in "$committed"/*; do
  name=$(basename "$path")
  sed '/^ *"build": /d' "$path" > "$tmp/committed"
  sed '/^ *"build": /d' "$regenerated/$name" > "$tmp/regenerated"
  if cmp -s "$tmp/committed" "$tmp/regenerated"; then
    echo "$name: identical apart from the build line"
  else
    echo "$name differs from the regenerated file (first 40 lines of the diff):" >&2
    diff "$tmp/committed" "$tmp/regenerated" | head -n 40 >&2 || true
    status=1
  fi
done
exit $status
