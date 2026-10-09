#!/bin/sh
# Fetch pinned, account-free sponsor tools into an ignored directory and
# verify each download against a recorded SHA-256. A mismatch deletes the
# file and fails; versions change only by editing the pins below.
set -eu
TOOLS="${RG_SPONSOR_TOOLS:?set RG_SPONSOR_TOOLS to an ignored directory}"
CH_VERSION=26.8.22.13
CH_URL="https://github.com/ClickHouse/ClickHouse/releases/download/v$CH_VERSION-lts/clickhouse-macos-aarch64"
CH_SHA256=015a56230b2474fa13e39f627e8f7ba6155fa9c666419646354173bd869e1c54
MONGO_VERSION=8.0.4
MONGO_URL="https://fastdl.mongodb.org/osx/mongodb-macos-arm64-$MONGO_VERSION.tgz"
MONGO_SHA256=219e3b3d7b31c049ff7bcf7470d38eff704e56df2ac18d4df78425e2985ccf58
SEMGREP_VERSION=1.180.0

[ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || { echo "pins cover macOS arm64 only" >&2; exit 1; }
mkdir -p "$TOOLS"
cd "$TOOLS"

fetch() { # url file sha256
  if [ ! -f "$2" ]; then
    curl -fsSL -o "$2.partial" "$1"
    mv "$2.partial" "$2"
  fi
  if ! echo "$3  $2" | shasum -a 256 -c - >/dev/null; then
    rm -f "$2"
    echo "SHA-256 mismatch for $2 from $1" >&2
    exit 1
  fi
}

fetch "$CH_URL" "clickhouse-$CH_VERSION" "$CH_SHA256"
chmod +x "clickhouse-$CH_VERSION"
fetch "$MONGO_URL" "mongodb-$MONGO_VERSION.tgz" "$MONGO_SHA256"
[ -d "mongodb-macos-aarch64-$MONGO_VERSION" ] || tar xzf "mongodb-$MONGO_VERSION.tgz"

"./clickhouse-$CH_VERSION" --version
"./mongodb-macos-aarch64-$MONGO_VERSION/bin/mongod" --version | head -1
uvx --from "semgrep==$SEMGREP_VERSION" semgrep --version
