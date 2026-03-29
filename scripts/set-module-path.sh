#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 github.com/owner/repo" >&2
  exit 1
fi

NEW_PATH="$1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

OLD_PATH="$(go list -m)"
go mod edit -module "$NEW_PATH"

for file in cmd/sapblob/main.go cmd/wasm/main.go README.md web/help.html web/install.html; do
  sed -i.bak "s|${OLD_PATH}|${NEW_PATH}|g" "$file"
  rm -f "${file}.bak"
done

go mod tidy
gofmt -w cmd/sapblob/main.go cmd/wasm/main.go sapblob.go sapblob_test.go

echo "Updated module path: ${OLD_PATH} -> ${NEW_PATH}"
