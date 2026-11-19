#!/usr/bin/env bash
# Publishes the version in Cargo.toml to crates.io, unless crates.io already has it, so
# a release run that stopped after publishing can be rerun to finish the tag.
set -euo pipefail

: "${CARGO_REGISTRY_TOKEN:?set CARGO_REGISTRY_TOKEN to a crates.io token}"
VERSION=$(python3 .github/scripts/version.py current)

# The sparse index lists every published version, one JSON object a line. It answers
# 404 until the first publish, which leaves the version unpublished as it should.
if curl -fsS https://index.crates.io/gj/al/gjallar | jq -e --arg version "$VERSION" 'select(.vers == $version)' >/dev/null; then
  echo "gjallar $VERSION is already on crates.io"
  exit 0
fi
cargo publish --locked
