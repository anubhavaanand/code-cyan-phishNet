/**
 * PhishNet Offscreen Document
 * Loads and runs the Transformers.js model for phishing detection
 */

import { pipeline, env } from '../vendor/transformers.min.js';
import logger from './utils/logger.js';
import { truncateText } from './utils/truncate-text.mjs';
import { normalizePredictions, labelSpaceSize, labelTable } from './utils/model-labels.mjs';
import { createInferenceGuard } from './utils/inference-guard.mjs';
import { canSend, createNotifier } from './utils/background-notify.mjs';
import { shouldHandle } from './utils/offscreen-messages.mjs';
import { buildReasons } from './utils/reason-builder.mjs';
import { warmupKey, isWarmed, markWarmed } from './utils/warmup-cache.mjs';
// Side-effect import: installs globalThis.PhishNet (shared v1.1 detection
// engine — skeletoning, Damerau typosquats, hardened URL checks)
import './utils/heuristic-detector.js';

const {
  isUrlSuspicious,
  isDomainSuspicious,
  checkLookalikeBrand
} = globalThis.PhishNet;

// Configure Transformers.js environment
env.allowLocalModels = false; // Download from Hugging Face Hub, then cache in IndexedDB
env.allowRemoteModels = true;
env.useBrowserCache = true;
env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('vendor/ort-wasm/');
env.backends.onnx.wasm.numThreads = 1; // Single thread for browser compatibility

// Model configuration
const MODEL_ID = 'onnx-community/phishing-email-detection-distilbert_v2.4.1-ONNX';

// Pinned revision. Without this the fetch resolves to whatever `main` points
// at, so a mutated or replaced model would be loaded and executed in this
// document's WASM context. The sha is the commit this extension was tested
// against; bump it deliberately, never implicitly.
// Verify with: curl -sL https://huggingface.com/api/models/<MODEL_ID> | jq -r .sha
const MODEL_REVISION = '8b488fdbc432690dd9323f5fd8119c5f3290b46b';

const MODEL_OPTIONS = {
  dtype: 'q8',            // Quantized for smaller size (~50MB)
  device: 'auto',         // Use WebGPU if available, fallback to WASM
  revision: MODEL_REVISION
};

// State
let classifier = null;
let modelLoaded = false;
let loadAttempts = 0;
const MAX_LOAD_ATTEMPTS = 3;

// Guards the single in-flight inference: timeout, supersession, and the
// request id used to drop stale results.
const guard = createInferenceGuard();

// Every message to the service worker goes through this. The worker can be
// suspended between a scan finishing and the reply being sent, and during
// shutdown sendMessage can throw rather than reject, so an unguarded call is
// either an unhandled rejection or a lost status with no trace.
const notify = createNotifier(
  (message) => chrome.runtime.sendMessage(message),
  (message, error) => {
    if (!canSend(chrome.runtime)) {
      logger.debug(`Dropped ${message.type}: extension context is gone`);
      return;
    }
    logger.debug(`Dropped ${message.type}: ${error?.message || error}`);
  }
);

/** Report model status to the background worker, or drop it quietly. */
function reportModelStatus(status, extra = {}) {
  return notify({ type: status, ...extra });
}

// requestId -> the run that owns it, so a late reply can be matched against the
// run the caller is actually waiting for. The entry is cleared by the reply
// itself, not by runInference's finally block: that block runs before the
// caller's .then, so clearing here would make every result look stale.
const requestRuns = new Map();

/**
 * Record which run owns a request id.
 * @param {string|null|undefined} requestId
 * @param {{requestId: string|null}} run
 */
function rememberRun(requestId, run) {
  if (requestId !== null && requestId !== undefined) requestRuns.set(requestId, run);
}

/**
 * Whether the reply for `requestId` may still be delivered.
 *
 * @param {string|null|undefined} requestId
 * @returns {boolean}
 */
function isLiveRequest(requestId) {
  if (requestId === null || requestId === undefined) return true;
  if (!requestRuns.has(requestId)) return false;
  return guard.owns(requestId);
}

/**
 * Initialize and load model with retry logic
 */
async function init() {
  logger.debug('Initializing offscreen document...');

  while (loadAttempts < MAX_LOAD_ATTEMPTS && !modelLoaded) {
    loadAttempts++;
    logger.debug(`Model load attempt ${loadAttempts}/${MAX_LOAD_ATTEMPTS}`);

    try {
      // Report progress
      reportProgress(Math.min(15 * loadAttempts, 35), `Loading model (attempt ${loadAttempts})...`);

      // Load classification pipeline (handles tokenizer internally)
      classifier = await pipeline('text-classification', MODEL_ID, MODEL_OPTIONS);

      // Warm up with a dummy inference, but only once per model build per
      // browser session. The offscreen document is recreated on RELOAD_MODEL
      // and when the browser reclaims it under memory pressure, and each
      // recreation used to pay for the same warm-up again.
      const key = warmupKey(MODEL_ID, MODEL_REVISION, MODEL_OPTIONS.dtype);
      const sessionStore = chrome.storage?.session;
      const alreadyWarmed = sessionStore ? await isWarmed(sessionStore, key) : false;

      if (alreadyWarmed) {
        logger.debug('Model already warmed up this session; skipping dummy inference');
      } else {
        reportProgress(80, 'Warming up model...');
        await classifier('Test email for warmup');
        if (sessionStore) await markWarmed(sessionStore, key);
      }

      reportProgress(100, 'Model ready');
      modelLoaded = true;

      // Notify background
      await reportModelStatus('OFFSCREEN_READY');
      logger.debug('Model loaded successfully');
      return;

    } catch (error) {
      logger.error(`Model load attempt ${loadAttempts} failed:`, error);
      
      if (loadAttempts >= MAX_LOAD_ATTEMPTS) {
        logger.error('All model load attempts failed');
        await reportModelStatus('OFFSCREEN_ERROR', {
          error: `Failed to load model after ${MAX_LOAD_ATTEMPTS} attempts: ${error.message}`
        });
        return;
      }
      
      // Wait before retry
      await new Promise(r => setTimeout(r, 2000 * loadAttempts));
    }
  }
}

/**
 * Report loading progress to background
 */
function reportProgress(progress, message) {
  return notify({
    type: 'MODEL_LOAD_PROGRESS',
    progress,
    message
  });
}

/**
 * Run inference on email text with timeout protection.
 *
 * Only one run is in flight at a time. A second request supersedes the first,
 * so a slow scan cannot overlap a newer one and two results cannot race to the
 * same caller.
 */
async function runInference(payload = {}, settings = {}, requestId = null) {
  if (!classifier || !modelLoaded) {
    throw new Error('Model not loaded');
  }

  const text = typeof payload === 'string' ? payload : (payload?.text || '');
  const sender = payload && typeof payload === 'object' ? payload.sender : undefined;
  const links = payload && typeof payload === 'object' ? payload.links : undefined;
  const hasFormElements = payload && typeof payload === 'object' && payload.hasFormElements === true;

  const run = guard.begin(requestId);
  rememberRun(requestId, run);

  // The vendored Transformers.js build takes no AbortSignal, so the WASM work
  // behind this promise cannot be interrupted from here. What is controllable
  // is everything after the model returns: an abandoned run drops its result
  // instead of spending CPU on reasons nobody will read.
  const work = (async () => {
    const startTime = performance.now();

    // Truncate text to 512 tokens (approximate: 1 token ≈ 4 chars)
    const truncatedText = truncateText(text, 512);

    // Run classification. Ask for every class the checkpoint declares rather
    // than a hard-coded 4: a binary model would otherwise have classes
    // silently dropped, and the remaining scores would be reported as the
    // whole picture.
    const results = await classifier(truncatedText, { topk: labelSpaceSize(classifier) });

    // Superseded or timed out while the model was running: stop here rather
    // than produce a result that will be thrown away. The vendored runtime
    // takes no AbortSignal, so this is the only point at which an abandoned
    // run can be dropped instead of running to completion.
    if (run.timedOut) {
      throw new Error('Inference abandoned after timeout');
    }
    if (!guard.isCurrent(run)) {
      throw new Error('Inference superseded by a newer request');
    }

    const processingTime = Math.round(performance.now() - startTime);

    // Process results, translating whatever the checkpoint calls its classes
    // onto our four canonical names. The checkpoint's own id2label table is
    // passed through so a class is identified by the name the model emitted,
    // not by where it landed in a score-sorted array.
    const predictions = normalizePredictions(results, labelTable(classifier));

    const topPrediction = predictions[0];
    const label = topPrediction?.label || 'uncertain';
    const confidence = topPrediction?.score || 0;

    // Generate reasons from the structured sender and links when the payload
    // carries them, falling back to the text otherwise.
    const reasons = generateReasons(predictions, text, settings, { sender, links, hasFormElements });

    return {
      label,
      confidence,
      reasons,
      processingTime,
      allScores: predictions.reduce((acc, p) => {
        acc[p.label] = p.score;
        return acc;
      }, {})
    };
  })();

  // The guard keeps pointing at this run after it settles. That is what lets
  // the reply handler tell "this is still the latest run" from "a newer request
  // superseded this one"; `begin()` is what replaces it. `requestRuns` is
  // consumed by the reply handler, not cleared here, because that handler runs
  // after this promise settles.
  return guard.run(work, run);
}

/**
 * Generate human-readable reasons.
 *
 * Structured `sender` and `links` are used when the payload carries them; the
 * text fallbacks cover callers that only have the subject and body.
 */
function generateReasons(predictions, text = '', settings = {}, structured = {}) {
  return buildReasons({
    predictions,
    text,
    sender: structured.sender,
    links: structured.links,
    hasFormElements: structured.hasFormElements,
    settings,
    detector: { isUrlSuspicious, isDomainSuspicious, checkLookalikeBrand }
  });
}

/**
 * Handle messages from background.
 *
 * This document owns exactly one message type, RUN_INFERENCE. Every other type
 * belongs to the background worker, and `chrome.runtime.sendMessage` delivers
 * to all contexts at once — so claiming a message it does not own would win the
 * race against the real handler, since Chrome keeps the first `sendResponse` it
 * sees. Returning false without responding leaves the message for its owner.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!shouldHandle(message, sender, chrome.runtime.id)) return false;

  runInference(message.payload || {}, message.settings || {}, message.requestId)
    .then(result => {
      // A result for a superseded run is dropped here as well as inside
      // runInference: the caller may have moved on since, and answering it
      // would overwrite a newer scan's verdict.
      if (!isLiveRequest(message.requestId)) return;
      requestRuns.delete(message.requestId);
      notify({
        type: 'INFERENCE_RESULT',
        requestId: message.requestId,
        result
      });
    })
    .catch(error => {
      requestRuns.delete(message.requestId);
      notify({
        type: 'INFERENCE_ERROR',
        requestId: message.requestId,
        error: error.message
      });
    });

  sendResponse({ success: true });
  return true;
});

// Initialize on load
init();
