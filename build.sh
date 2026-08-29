#!/usr/bin/env bash
set -euo pipefail

# Build the TeaTun binary. Run from the repo root.
#   ./build.sh              -> build for the host, into ./dist/teatun
#   ./build.sh all          -> build linux amd64 + arm64 into ./dist/
VERSION="${VERSION:-2.0.0}"
LDFLAGS="-s -w -X main.version=${VERSION}"
OUT="dist"
mkdir -p "$OUT"

build() {
    local goos="$1" goarch="$2" out="$3"
    echo ">> building $goos/$goarch -> $out"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/teatun
}

case "${1:-host}" in
    all)
        build linux amd64 "$OUT/teatun-linux-amd64"
        build linux arm64 "$OUT/teatun-linux-arm64"
        cp "$OUT/teatun-linux-amd64" "$OUT/teatun"
        ;;
    *)
        build "$(go env GOOS)" "$(go env GOARCH)" "$OUT/teatun"
        ;;
esac

echo "done. artifacts in ./$OUT/"
ls -la "$OUT"
