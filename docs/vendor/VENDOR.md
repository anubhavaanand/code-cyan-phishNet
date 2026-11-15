# Vendored: three.module.js

The landing page hero imports this directly:

```js
// docs/index.html:468
import * as THREE from './vendor/three.module.js';
```

## Current pin

| | |
| --- | --- |
| Upstream | `three` on npm |
| Revision | **r160** (`const REVISION = '160'`) |
| Size | 1,272,972 bytes |
| SHA-256 | `76dea8151bc9352aef3528b4262e249b2604f62543828328db978d060d61a495` |

r160 is the last release whose `three.module.js` is **self-contained**. From r167
onward the module build imports `./three.core.js`, so a current release needs two
files totalling ~2.13 MB — a 68% size increase over what is vendored here. For a
marketing page hero that is a bad trade, which is why this stays on r160.

## Verify the vendored file

```bash
sha256sum docs/vendor/three.module.js
# expect 76dea8151bc9352aef3528b4262e249b2604f62543828328db978d060d61a495
```

## Update procedure

```bash
./scripts/update-three.sh <version>
```

The script downloads the release from npm, verifies the module imports nothing
outside itself, writes both files if the release is split, and prints the new
hash for this file. It does **not** commit — review the diff first.

## APIs this page actually uses

`WebGLRenderer`, `Scene`, `FogExp2`, `PerspectiveCamera`, `AmbientLight`,
`DirectionalLight`, `BufferGeometry`, `Float32BufferAttribute`, `LineSegments`,
`LineBasicMaterial`.

All are stable across r160–r187, so a version bump is low-risk if the size cost
is ever accepted.

## Tree-shaking

The remaining size win is a bundler: importing named exports from `three` and
building `docs/` with Rollup would drop the unused shader chunks and the WebGPU
path. That needs a build step for the landing page, which does not exist yet.
The issue that prompted this file (#195) asks for it; it is not done here.

## Provenance limits

The npm package ships no build metadata beyond the version, so this file records
the version and hash — not the exact upstream commit. Verifying a checkout means
comparing the hash above.