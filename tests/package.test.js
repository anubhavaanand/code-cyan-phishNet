/**
 * Package integrity tests.
 *
 * These guard the invariants that make the built artifact loadable at all —
 * the class of bug where the manifest points at a file that was never built.
 * Run `npm test` (which builds first) so dist/ is populated.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const exists = (p) => fs.existsSync(path.join(ROOT, p));
const manifest = JSON.parse(read('manifest.json'));
const pkg = JSON.parse(read('package.json'));

const REQUIRED_FIELDS = [
  'manifest_version',
  'name',
  'version',
  'description',
  'icons',
  'action',
  'background',
  'content_scripts',
  'permissions',
  'host_permissions',
  'content_security_policy',
];

describe('manifest', () => {
  test('is manifest version 3', () => {
    assert.equal(manifest.manifest_version, 3);
  });

  test('declares every required field', () => {
    for (const field of REQUIRED_FIELDS) {
      assert.ok(field in manifest, `manifest is missing "${field}"`);
    }
  });

  test('version matches package.json', () => {
    assert.equal(manifest.version, pkg.version, 'manifest and package.json versions must agree');
  });

  test('every manifest-referenced file exists', () => {
    const refs = [
      ...Object.values(manifest.icons),
      ...Object.values(manifest.action.default_icon || {}),
      manifest.action.default_popup,
      manifest.background.service_worker,
      ...manifest.content_scripts.flatMap((cs) => [...cs.js, ...(cs.css || [])]),
    ].filter(Boolean);

    const missing = refs.filter((p) => !exists(p));
    assert.deepEqual(missing, [], `missing files: ${missing.join(', ')}`);
  });

  test('popup and options pages are built into dist/', () => {
    assert.equal(manifest.action.default_popup, 'dist/popup.html');
    assert.ok(exists('dist/popup.html'), 'run `npm run build` before `npm test`');
    assert.ok(exists('dist/options.html'), 'run `npm run build` before `npm test`');
  });

  test('built HTML references only files that exist', () => {
    for (const page of ['dist/popup.html', 'dist/options.html']) {
      if (!exists(page)) continue;
      const html = read(page);
      const refs = [...html.matchAll(/(?:src|href)="(\.\/[^"]+)"/g)].map((m) => m[1]);
      assert.ok(refs.length > 0, `${page} references no assets`);
      for (const ref of refs) {
        const target = path.join('dist', ref.replace(/^\.\//, ''));
        assert.ok(exists(target), `${page} references missing ${ref}`);
      }
    }
  });

  test('declares only the API permissions the worker actually uses', () => {
    for (const perm of ['storage', 'offscreen']) {
      assert.ok(manifest.permissions.includes(perm), `missing permission: ${perm}`);
    }
    for (const perm of ['activeTab', 'scripting']) {
      assert.ok(!manifest.permissions.includes(perm), `unused permission: ${perm}`);
    }
  });

  test('does not duplicate the Hugging Face host grant', () => {
    const hosts = manifest.host_permissions.filter((pattern) => pattern.includes('huggingface.co'));
    assert.deepEqual(hosts, ['https://*.huggingface.co/*']);
  });

  test('registers content scripts for Gmail and Outlook', () => {
    const matches = manifest.content_scripts.flatMap((cs) => cs.matches).join(' ');
    assert.match(matches, /mail\.google\.com/);
    assert.match(matches, /outlook\.live\.com/);
    assert.match(matches, /outlook\.office\.com/);
  });

  test('keeps bundled inference binaries and icons private to extension pages', () => {
    // The offscreen document and manifest icons are extension-owned. They do
    // not require web_accessible_resources, which exposes files to websites.
    assert.deepEqual(manifest.web_accessible_resources || [], []);
    assert.match(read('src/offscreen.js'), /chrome\.runtime\.getURL\('vendor\/ort-wasm\/'\)/);
    assert.ok(exists('public/offscreen.html'));
    assert.ok(exists('vendor/ort-wasm/'), 'WASM binaries must remain bundled');
  });
});

describe('content security policy', () => {
  const csp = manifest.content_security_policy.extension_pages;
  const S = (s) => `'${s}'`;
  const ALLOWED = {
    'script-src': [S('self'), S('wasm-unsafe-eval'), S('wasm-eval'), S('none'), S('inline-speculation-rules')],
    'object-src': [S('self'), S('none')],
    'worker-src': [S('self'), S('none')],
  };

  test('allows wasm but no remote script sources', () => {
    for (const directive of csp.split(';').map((d) => d.trim().split(/\s+/)).filter((d) => d.length)) {
      const [name, ...values] = directive;
      assert.ok(name in ALLOWED, `unknown CSP directive: ${name}`);
      for (const value of values) {
        assert.ok(!/^https?:\/\//.test(value), `remote URL in ${name}: ${value}`);
        assert.ok(ALLOWED[name].includes(value), `disallowed value ${value} in ${name}`);
      }
    }
  });

  test('permits wasm-unsafe-eval for the ONNX runtime', () => {
    assert.ok(csp.includes("'wasm-unsafe-eval'"));
  });
});

describe('vendored dependencies', () => {
  // The bundles are checked in and loaded from the extension origin under a
  // strict CSP, so nothing in package.json records them. VENDOR.md is that
  // record, and these tests are what keeps it true.
  const VENDOR = read('VENDOR.md');
  const crypto = require('node:crypto');
  const sha256 = (file) => crypto.createHash('sha256')
    .update(fs.readFileSync(path.join(ROOT, file)))
    .digest('hex');

  const BUNDLES = {
    'vendor/transformers.min.js': '22266dbd81a41ed97699215a63a67e416662d70cc5f3e2d98215220d234c698d',
    'vendor/ort-wasm/ort-wasm-simd-threaded.jsep.mjs': '3014f077d2d51ffd2174d3bcb72df482b897b81828cb3082d63e9c0a601fa3d4',
    'vendor/ort-wasm/ort-wasm-simd-threaded.jsep.wasm': 'f125583adb98686fe44ac652a924657479b48495fecb19c6e67d4f6ea84277df',
  };

  test('every vendored bundle matches its recorded hash', () => {
    for (const [file, expected] of Object.entries(BUNDLES)) {
      assert.equal(sha256(file), expected, `${file} changed without updating VENDOR.md`);
    }
  });

  test('VENDOR.md records every vendored bundle and its version', () => {
    for (const file of Object.keys(BUNDLES)) {
      assert.ok(VENDOR.includes(file), `VENDOR.md does not mention ${file}`);
    }
    assert.match(VENDOR, /@huggingface\/transformers/);
    assert.match(VENDOR, /onnxruntime-web/);
    assert.match(VENDOR, /3\.0\.0/);
    assert.match(VENDOR, /1\.20\.0/);
  });

  test('VENDOR.md lists the hash of every bundle', () => {
    for (const hash of Object.values(BUNDLES)) {
      assert.ok(VENDOR.includes(hash), `hash ${hash} missing from VENDOR.md`);
    }
  });
});

describe('model provenance', () => {
  const OFFSCREEN = read('src/offscreen.js');

  test('the model fetch is pinned to an exact revision', () => {
    // Without a revision the fetch resolves to whatever `main` points at, so a
    // mutated or replaced model would be loaded and executed here.
    const match = OFFSCREEN.match(/const MODEL_REVISION = '([0-9a-f]{40})'/);
    assert.ok(match, 'MODEL_REVISION must be a full 40-character commit sha');
    assert.match(OFFSCREEN, /revision: MODEL_REVISION/);
  });

  test('the revision pin is documented as deliberate', () => {
    assert.match(OFFSCREEN, /Pinned revision/);
  });
});

describe('production source hygiene', () => {
  const CI = read('.github/workflows/ci.yml');

  test('the console.log gate catches bracket notation', () => {
    // The old gate was a line-based `grep -v`, which missed console['log']
    // and console["log"] entirely. Pin the pattern that replaced it.
    assert.ok(
      CI.includes('grep -rnE "console'),
      'gate must use an extended regex, not a literal grep'
    );
    assert.ok(
      CI.includes('console\\s*\\.\\s*log'),
      'gate must match console.log including whitespace'
    );
    assert.ok(
      CI.includes('console\\s*\\['),
      'gate must match console["log"] bracket notation'
    );
    assert.ok(
      !CI.includes('grep -r "console\\.log" src/'),
      'the fragile line-based grep must not return'
    );
  });

  test('the CSP gate matches any script tag and inline handlers', () => {
    assert.match(CI, /<script\[\[:space:\]>\]/);
    assert.match(CI, /\\son\[a-z\]\+\[\[:space:\]\]\*=/);
    assert.doesNotMatch(
      CI,
      /grep -r "<script>" src\//,
      'the exact-literal script grep must not return'
    );
  });

  test('new-tab links in shipped HTML cannot access the opener', () => {
    const htmlFiles = [
      'docs/index.html',
      'frontend/options.html',
      'frontend/popup.html',
      'public/offscreen.html',
      'src/popup.html',
    ];
    let checked = 0;
    for (const file of htmlFiles) {
      for (const [link] of read(file).matchAll(/<a\b[^>]*>/gi)) {
        if (!/\btarget\s*=\s*["']_blank["']/i.test(link)) continue;
        checked += 1;
        assert.match(link, /\brel\s*=\s*["'][^"']*\bnoopener\b[^"']*["']/i, `${file}: ${link}`);
        if (file === 'src/popup.html') {
          assert.match(link, /\brel\s*=\s*["'][^"']*\bnoreferrer\b[^"']*["']/i, `${file}: ${link}`);
        }
      }
    }
    assert.ok(checked > 0, 'expected at least one new-tab link');
  });

  const SRC_FILES = [
    'src/background.js',
    'src/offscreen.js',
    'src/content.js',
    'src/popup.js',
    'src/selectors.js',
    'src/utils/logger.js',
    'src/utils/error-boundary.js',
    'src/utils/heuristic-detector.js',
  ].filter(exists);

  test('contains no eval or new Function', () => {
    for (const file of SRC_FILES) {
      const src = read(file);
      assert.ok(!/\beval\s*\(/.test(src), `${file} uses eval()`);
      assert.ok(!/new\s+Function\s*\(/.test(src), `${file} uses new Function()`);
    }
  });

  test('contains no unguarded console.log', () => {
    for (const file of SRC_FILES) {
      const src = read(file);
      // logger.js is the logging facade; its console calls are IS_DEBUG-gated.
      const offenders = src
        .split('\n')
        .map((line, i) => ({ line, n: i + 1 }))
        .filter(({ line }) => /console\.log\s*\(/.test(line) && !/IS_DEBUG/.test(line));
      assert.deepEqual(
        offenders.map((o) => `line ${o.n}`),
        [],
        `${file} has console.log`
      );
    }
  });

  test('no source file uses innerHTML with interpolated data', () => {
    for (const file of SRC_FILES) {
      const src = read(file);
      assert.ok(!/\.innerHTML\s*=/.test(src), `${file} assigns innerHTML`);
    }
  });
});

describe('marketing site security', () => {
  const site = read('docs/index.html');

  test('mock phishing links use a listener rather than an inline handler', () => {
    assert.doesNotMatch(site, /\sonclick\s*=/i);
    assert.match(site, /data-preview-link="inert"/);
    assert.match(site, /querySelector\('\[data-preview-link="inert"\]'\)\?\.addEventListener\('click',\s*\(event\)\s*=>\s*event\.preventDefault\(\)\)/);
  });

  test('preview diagnostics are opt-in and do not publish a frame counter', () => {
    assert.match(site, /const demoDebug = new URLSearchParams/);
    assert.match(site, /if \(demoDebug\) console\.warn\(/);
    assert.doesNotMatch(site, /window\.__pnRenders/);
  });
});

describe('history privacy reset', () => {
  test('Firefox clears extension-local data, matching the Chrome worker', () => {
    const firefox = read('src/background-firefox.js');
    assert.match(firefox, /case 'CLEAR_HISTORY':\s*await browser\.storage\.local\.clear\(\)/);
  });
});

describe('test-email playground DOM safety', () => {
  test('clears test messages without assigning HTML strings', () => {
    const source = read('public/test-emails.html');
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
    assert.match(source, /list\.replaceChildren\(\)/);
  });
});

describe('module syntax', () => {
  test('every ES module source parses', () => {
    const esm = ['src/background.js', 'src/offscreen.js', 'src/utils/logger.js'];
    for (const file of esm) {
      assert.doesNotThrow(
        () => execFileSync(process.execPath, ['--check', '--input-type', 'module'], {
          input: read(file),
          stdio: ['pipe', 'pipe', 'pipe'],
        }),
        `${file} has a syntax error`
      );
    }
  });

  test('every classic script source parses', () => {
    const scripts = [
      'src/selectors.js',
      'src/utils/error-boundary.js',
      'src/utils/heuristic-detector.js',
      'src/content.js',
    ];
    for (const file of scripts) {
      assert.doesNotThrow(
        () => execFileSync(process.execPath, ['--check', path.join(ROOT, file)], { stdio: 'pipe' }),
        `${file} has a syntax error`
      );
    }
  });
});

describe('required project files', () => {
  test('Firefox packaging excludes the email test playground', () => {
    const buildScript = read('build-firefox.sh');
    assert.match(buildScript, /rm -f dist-firefox\/public\/test-emails\.html/);
  });

  test('Dependabot does not silently exclude all major dependency updates', () => {
    const config = read('.github/dependabot.yml');
    assert.doesNotMatch(config, /dependency-name:\s*["']?\*["']?/);
  });

  test('ships the files the store listing and license require', () => {
    for (const file of ['LICENSE', 'README.md', 'PRIVACY_POLICY.md', 'CHANGELOG.md', 'CONTRIBUTING.md']) {
      assert.ok(exists(file), `missing ${file}`);
    }
  });

  test('ships icons at every declared size', () => {
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    for (const size of [16, 32, 48, 128]) {
      const p = `public/icons/icon-${size}.png`;
      assert.ok(exists(p), `missing ${p}`);
      const bytes = fs.readFileSync(path.join(ROOT, p));
      assert.equal(bytes[0], 0x89, `${p} is not a PNG`);
      assert.equal(bytes.readUInt32BE(1), 0x504e470d, `${p} is not a PNG`);
    }
  });
});
