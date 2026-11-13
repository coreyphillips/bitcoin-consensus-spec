#!/bin/sh
# usage: fetch-bitcoind.sh DIR
#
# Downloads the Bitcoin Core release the block corpus was recorded from, for
# this Linux machine, from bitcoincore.org into DIR. Checks it against the
# SHA-256 in conformance/recorder/pins.json (the values the recorder image
# also pins), unpacks it there and prints the path of its bitcoind.
set -eu

dir=$1
pins="$(dirname "$0")/../conformance/recorder/pins.json"

case "$(uname -s) $(uname -m)" in
  "Linux x86_64") platform=x86_64-linux-gnu ;;
  "Linux aarch64") platform=aarch64-linux-gnu ;;
  *) echo "no pinned Bitcoin Core release for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

version=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["core"]["version"].lstrip("v"))' "$pins")
file="bitcoin-$version-$platform.tar.gz"
sha=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["core"]["release_tarballs"][sys.argv[2]])' "$pins" "$file")

mkdir -p "$dir"
curl -fsSL --retry 3 -o "$dir/$file" "https://bitcoincore.org/bin/bitcoin-core-$version/$file"
# An explicit comparison, because some sha256sum -c accept a malformed line.
actual=$(sha256sum "$dir/$file" | cut -d ' ' -f 1)
if [ "$actual" != "$sha" ]; then
  echo "$file has SHA-256 $actual, pins.json has $sha" >&2
  exit 1
fi
echo "$file: SHA-256 $actual, as pinned" >&2
tar -xzf "$dir/$file" -C "$dir"
echo "$dir/bitcoin-$version/bin/bitcoind"
