# Vendored dependencies

PhishNet ships two third-party bundles so the extension can run entirely
on-device with no network access at runtime. Both are checked into `vendor/`
and are loaded by `src/offscreen.js` inside the offscreen document.

Neither is fetched at runtime, and neither is covered by npm — so nothing in
`package.json` records what they are. This file is that record.

## What is vendored

| File | Size | Upstream | Version |
| --- | --- | --- | --- |
| `vendor/transformers.min.js` | 743,608 B | `@huggingface/transformers` | **3.0.0** |
| `vendor/ort-wasm/ort-wasm-simd-threaded.jsep.mjs` | 46,838 B | `onnxruntime-web` | **1.20.0** |
| `vendor/ort-wasm/ort-wasm-simd-threaded.jsep.wasm` | 21,649,119 B | `onnxruntime-web` | **1.20.0** |

Version strings were read out of the bundles themselves, not from memory:

- `@huggingface/transformers` embeds `version:"3.0.0"` in its env block
- the ORT wasm binary reports `1.20.0`

The `.jsep` ORT build is the one that includes the WebGPU and WebNN execution
providers, which is why `device: 'auto'` in `src/offscreen.js` can resolve to
`webgpu` before falling back to `wasm`.

## Integrity hashes

SHA-256 of each file exactly as committed. `tests/package.test.js` asserts
these, so replacing a bundle without updating this file fails CI.

```
76726d6868963587407b2e13f671a368429e359979e16f822c5d6bee2d2dd38d  vendor/transformers.min.js
3014f077d2d51ffd2174d3bcb72df482b897b81828cb3082d63e9c0a601fa3d4  vendor/ort-wasm/ort-wasm-simd-threaded.jsep.mjs
f125583adb98686fe44ac652a924657479b48495fecb19c6e67d4f6ea84277df  vendor/ort-wasm/ort-wasm-simd-threaded.jsep.wasm
```

Verify a checkout:

```bash
sha256sum vendor/transformers.min.js vendor/ort-wasm/*
```

Compare the output against the table above.

## Why these files and not npm

The extension must load them from its own origin under a strict CSP
(`script-src 'self' 'wasm-unsafe-eval'`). An npm install would place them in
`node_modules/`, which is not reachable from the extension pages, and a
content delivery network is disallowed by both the CSP and the privacy
posture — PhishNet makes no network requests at all.

That is also why there is no lockfile entry: these are build artefacts copied
into the tree, not resolved dependencies.

## Upgrading

1. Fetch the new bundle from the upstream release, not from a CDN mirror.
2. Replace the file in `vendor/`.
3. Update the version and hash table above.
4. Update the expected hashes in `tests/package.test.js`.
5. Run `npm test` and load the unpacked extension in Chrome **and** Firefox —
   the ORT wasm path differs between the two and only a browser run proves
   inference still works.
6. Commit the bundle, this file and the test together, so the record and the
   artefact can never diverge.

## Provenance limits

These bundles are minified and carry no build metadata, so this file records
the version they report and their hash — not the exact upstream commit they
were built from. If an upstream release ever needs to be reproduced
byte-for-byte, the pinned version plus the hash is the verification path;
rebuilding from source is not currently scripted.
