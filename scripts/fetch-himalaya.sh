#!/bin/sh
# Downloads the official Himalaya v2.2.1 x86_64 Linux asset into a new,
# empty directory and verifies both the archive and the binary by sha256.
# Only the himalaya member is extracted. The official build is send-capable;
# the wrapper accepts it only with allow_send_capable_build (tests only).
#
# Usage: fetch-himalaya.sh <new-empty-dir>
# Needs: curl, tar, coreutils. Result: <dir>/himalaya.
set -eu

URL=https://github.com/pimalaya/himalaya/releases/download/v2.2.1/himalaya.x86_64-linux.tgz
TGZ_SHA256=5c5ba2724c162f82d0a0c71b6c03224ed44f8bef7b14ace5da0635d3af2665a0
BIN_SHA256=03b5b077fa5227700a9196271ef1e7d053eb92eadbc535258a80762daddf5cb3

D=${1:?usage: fetch-himalaya.sh <new-empty-dir>}
if [ -e "$D" ] && [ -n "$(ls -A "$D")" ]; then
  echo "fetch-himalaya.sh: $D is not empty" >&2
  exit 1
fi
mkdir -p "$D"
D=$(cd "$D" && pwd)

curl -fsSL --proto '=https' -o "$D/himalaya.x86_64-linux.tgz" "$URL"
echo "$TGZ_SHA256  $D/himalaya.x86_64-linux.tgz" | sha256sum -c -
tar -xzf "$D/himalaya.x86_64-linux.tgz" -C "$D" --no-same-owner --no-same-permissions himalaya
if [ -L "$D/himalaya" ] || [ ! -f "$D/himalaya" ]; then
  echo "fetch-himalaya.sh: extracted himalaya is not a regular file" >&2
  exit 1
fi
echo "$BIN_SHA256  $D/himalaya" | sha256sum -c -
chmod 0755 "$D/himalaya"
env -i "$D/himalaya" --version
