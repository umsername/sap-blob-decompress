#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="$ROOT_DIR/web"
mkdir -p "$WEB_DIR"
GOOS=js GOARCH=wasm go build -o "$WEB_DIR/sapblob.wasm" "$ROOT_DIR/cmd/wasm"
GOROOT_DIR="$(go env GOROOT)"
if [[ -f "$GOROOT_DIR/lib/wasm/wasm_exec.js" ]]; then cp "$GOROOT_DIR/lib/wasm/wasm_exec.js" "$WEB_DIR/";
elif [[ -f "$GOROOT_DIR/misc/wasm/wasm_exec.js" ]]; then cp "$GOROOT_DIR/misc/wasm/wasm_exec.js" "$WEB_DIR/";
else echo "Could not find wasm_exec.js inside GOROOT=$GOROOT_DIR" >&2; exit 1; fi
touch "$WEB_DIR/.nojekyll"
echo "Built web demo into $WEB_DIR"
