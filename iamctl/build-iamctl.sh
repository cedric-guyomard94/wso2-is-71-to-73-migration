#!/usr/bin/env bash
# Construit IAMCTL (identity-tools-cli) depuis le tag officiel + patchs locaux, pour l'archi courante.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VERSION="${IAMCTL_VERSION:-v3.0.1}"
OUT="$HERE/bin/iamctl"
command -v go >/dev/null || { echo "Go est requis (https://go.dev/dl)"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git clone -q --depth 1 --branch "$VERSION" https://github.com/wso2-extensions/identity-tools-cli.git "$TMP/src" 2>/dev/null
for p in "$HERE"/patches/*.patch; do
  [ -e "$p" ] || continue
  echo "-> patch $(basename "$p")"
  git -C "$TMP/src" apply "$p"
done
mkdir -p "$(dirname "$OUT")"
(cd "$TMP/src/iamctl" && go build -o "$OUT" .)
echo "IAMCTL $VERSION (+patchs) -> $OUT"
