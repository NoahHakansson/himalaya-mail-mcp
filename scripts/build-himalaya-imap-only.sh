#!/bin/sh
# Builds an IMAP-only himalaya v2.2.1 (no SMTP, JMAP, Gmail, Graph, Sieve,
# pimdir, maildir, mbox) as a static musl binary, from the signed upstream tag.
#
# Usage: build-himalaya-imap-only.sh <new-empty-workdir>
# Needs: git, docker, and the maintainer key in the caller's gpg keyring
# (GNUPGHOME is honoured, so a throwaway keyring works):
#   curl -fsSL https://github.com/soywod.gpg | gpg --import
# Result: <workdir>/himalaya, plus its sha256 on stdout.
#
# The fetch step is the only one with network access; the compile runs with
# --network none. Output is reproducible up to the order of the feature names
# in `--version` (pimalaya-cli's build.rs iterates a HashMap), so a rebuild
# yields one of two binaries:
#   85d0cb1bf08727dd3674dad5ad787df7693fb0cbee84fb1e82b4d66fd183a810
#   dcbb5c07483118f91f0a4a7dd4a1e71c91f878483d94edafae76774d2918faca
# HMCP_BUILD_NAME sets the container name prefix (default hmcp-himalaya).
set -eu

REV=5b12b2a8c2c253b98f15c46610ad74cba2a182bc
TAG=v2.2.1
SIGNER=75F0AB7CFE01D077AEE6CAFD353E4A18EE0FAB72
IMG=rust:1.96.1-alpine@sha256:a41f7740f8b45d45795624eec13a8b42263cc700f19f7e4e86e04d3dda08a479
FEATURES=imap,rustls-ring
NAME=${HMCP_BUILD_NAME:-hmcp-himalaya}

W=${1:?usage: build-himalaya-imap-only.sh <new-empty-workdir>}
if [ -e "$W" ] && [ -n "$(ls -A "$W")" ]; then
  echo "build-himalaya-imap-only.sh: $W is not empty" >&2
  exit 1
fi
mkdir -p "$W/out"
W=$(cd "$W" && pwd)

git clone --quiet https://github.com/pimalaya/himalaya "$W/src"
git -C "$W/src" -c advice.detachedHead=false checkout --quiet "$REV"
test "$(git -C "$W/src" rev-parse "$TAG^{commit}")" = "$REV"
git -C "$W/src" verify-tag --raw "$TAG" 2>&1 | grep -q "VALIDSIG $SIGNER"

run() {
  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$W/src:/src:ro" -v "$W/out:/out" \
    -e HOME=/tmp -e CARGO_HOME=/out/cargo-home -e CARGO_TARGET_DIR=/out/target \
    -e GIT_REV="$REV" -e GIT_DESCRIBE="$TAG" \
    -w /src "$@"
}

run --name "$NAME-fetch" "$IMG" cargo fetch --locked
run --name "$NAME-build" --network none "$IMG" \
  cargo build --release --locked --offline --no-default-features --features "$FEATURES"

cp "$W/out/target/release/himalaya" "$W/himalaya"
sha256sum "$W/himalaya"
