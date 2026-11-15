#!/usr/bin/env bash
# Refresh the vendored three.js bundle used by the landing page hero.
#
#   ./scripts/update-three.sh 0.187.0
#
# Prints the new size and hash for docs/vendor/VENDOR.md. Does not commit.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: $0 <version>     e.g. $0 0.187.0" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "fetching three@$VERSION ..."
npm pack "three@$VERSION" --pack-destination "$TMP" --silent >/dev/null
tar -xzf "$TMP"/three-"$VERSION".tgz -C "$TMP"

SRC="$TMP/package/build/three.module.js"
[ -f "$SRC" ] || { echo "no build/three.module.js in the package" >&2; exit 1; }

# A self-contained module keeps the vendored size down. Recent releases split
# into three.module.js + three.core.js; say so rather than shipping both silently.
if grep -q "three.core.js" "$SRC"; then
  echo
    echo "NOTE: this release imports ./three.core.js."
  echo "      Vendoring it needs two files (~2.1 MB) instead of one."
  echo "      Refusing to install automatically — decide first."
  exit 3
fi

SIZE=$(wc -c < "$SRC")
echo "r$(node -e "const s=require('fs').readFileSync('$SRC','utf8');const m=s.match(/REVISION\\s*=\\s*['\"]([^'\"]+)/);console.log(m?m[1]:'?')")  ${SIZE} bytes"

cp "$SRC" docs/vendor/three.module.js
echo
echo "installed. new hash:"
sha256sum docs/vendor/three.module.js
echo
echo "Update the pin table and hash in docs/vendor/VENDOR.md, then commit"
echo "docs/vendor/three.module.js and docs/vendor/VENDOR.md together."