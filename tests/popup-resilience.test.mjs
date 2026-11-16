/**
 * Popup and modal resilience tests.
 *
 * Three low-severity findings share this area: the vanilla popup trusting a
 * partial `scanStats` record, a corrupt `scanHistory` entry aborting the render,
 * and the threat modal moving focus without trapping or restoring it.
 */
import { test, describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

const POPUP = new URL('../src/popup.js', import.meta.url);

/** Storage contents the popup will read, mutated per test. */
const storageData = {};

/** Minimal DOM: enough for the popup's stats and history render. */
function makeDom() {
  const make = (tag) => ({
    tag,
    style: {},
    children: [],
    className: '',
    textContent: '',
    title: '',
    value: '',
    checked: false,
    disabled: false,
    classList: { add() {}, remove() {}, toggle() {} },
    appendChild(child) { this.children.push(child); return child; },
    removeChild(child) { this.children = this.children.filter((c) => c !== child); },
    addEventListener() {},
    removeEventListener() {},
    setAttribute() {},
    getAttribute: () => null,
    querySelector: () => null,
    querySelectorAll: () => [],
    focus() {},
    remove() { this.removed = true; }
  });

  const nodes = new Map();
  for (const id of ['statTotal', 'statBlocked', 'statSafe', 'historyList']) {
    nodes.set(id, make('div'));
  }
  // Any other element the popup binds to: a stub that accepts listeners.
  const stubFor = (id) => {
    if (!nodes.has(id)) nodes.set(id, make('div'));
    return nodes.get(id);
  };

  const listeners = new Map();
  return {
    nodes,
    listeners,
    /** Fire the handler the popup registered for `event`. */
    fire(event) {
      for (const fn of listeners.get(event) || []) fn({ type: event });
    },
    document: {
      getElementById: (id) => stubFor(id),
      createElement: make,
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener: (event, fn) => {
        if (!listeners.has(event)) listeners.set(event, []);
        listeners.get(event).push(fn);
      },
      removeEventListener() {}
    }
  };
}

let bootCount = 0;

/**
 * Evaluate the popup with a fresh DOM and the shared `chrome` mock.
 *
 * The module is imported once per call (cache-busted) so its DOMContentLoaded
 * listener is registered against this run's document.
 */
async function renderPopup() {
  const dom = makeDom();
  globalThis.document = dom.document;
  // The popup polls on an interval; stub it so the test process can exit.
  globalThis.window = {
    addEventListener: (event, fn) => {
      const map = dom.listeners;
      if (!map.has(event)) map.set(event, []);
      map.get(event).push(fn);
    },
    location: { reload() {} }
  };
  globalThis.chrome = {
    storage: {
      local: {
        get: (_keys, cb) => cb({ ...storageData }),
        set: (values, cb) => { Object.assign(storageData, values); cb?.(); }
      }
    },
    runtime: { lastError: undefined, sendMessage: async () => null }
  };

  // Globals stay installed: the popup keeps using them from async callbacks
  // after init returns, and this file runs in its own process.
  await import(`${POPUP.href}?render=${++bootCount}`);
  // The popup initialises on DOMContentLoaded, which starts the poll timer.
  // init is async, so let it settle before tearing the timer down.
  dom.fire('DOMContentLoaded');
  await new Promise((r) => setTimeout(r, 120));
  // pagehide is how the popup clears that timer; firing it keeps the test
  // process from waiting on the poll interval.
  dom.fire('pagehide');
  await new Promise((r) => setTimeout(r, 10));
  return dom;
}

describe('vanilla popup resilience', () => {
  it('renders zeroes for a partial scanStats object', async () => {

    storageData.scanStats = { total: 5 }; // missing phishing/safe/trusted
    storageData.scanHistory = [];
    const dom = await renderPopup();
    await new Promise((r) => setTimeout(r, 30));

    assert.equal(dom.nodes.get('statTotal').textContent, '5');
    assert.equal(dom.nodes.get('statBlocked').textContent, '0');
    assert.equal(dom.nodes.get('statSafe').textContent, '0');
    // The bug rendered "undefined"/"NaN" for the missing fields.
    assert.equal(dom.nodes.get('statSafe').textContent.includes('undefined'), false);
  });

  it('renders zeroes for a non-numeric scanStats value', async () => {
    storageData.scanStats = { total: 'lots', phishing: null, safe: NaN };
    storageData.scanHistory = [];
    const dom = await renderPopup();
    await new Promise((r) => setTimeout(r, 30));

    assert.equal(dom.nodes.get('statTotal').textContent, '0');
    assert.equal(dom.nodes.get('statBlocked').textContent, '0');
  });

  it('does not throw when scanHistory is not an array', async () => {
    storageData.scanStats = {};
    storageData.scanHistory = { not: 'an array' };
    const dom = await renderPopup();
    await new Promise((r) => setTimeout(r, 30));

    // The history list falls back to the empty state rather than throwing
    // inside the storage callback and leaving stale markup behind.
    const list = dom.nodes.get('historyList');
    assert.equal(list.children.length, 1);
    assert.match(list.children[0].textContent, /No emails scanned yet/i);
  });

  it('skips a corrupt history entry instead of aborting the list', async () => {
    storageData.scanStats = { total: 2, phishing: 1, safe: 1, trusted: 0 };
    storageData.scanHistory = [null, 42, { subject: 'Good', sender: 'a@b.c', label: 'legitimate_email' }];
    const dom = await renderPopup();
    await new Promise((r) => setTimeout(r, 30));

    const list = dom.nodes.get('historyList');
    // Two corrupt entries are dropped; the valid one still renders.
    assert.equal(list.children.length, 1, `expected 1 row, got ${list.children.length}`);
  });
});