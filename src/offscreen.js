/**
 * PhishNet Offscreen Document
 * Loads and runs the Transformers.js model for phishing detection
 */

import { pipeline, env } from '../vendor/transformers.min.js';
import logger from './utils/logger.js';
import { truncateText } from './utils/truncate-text.mjs';
import { normalizePredictions, labelSpaceSize } from './utils/model-labels.mjs';
import { createInferenceGuard } from './utils/inference-guard.mjs';
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

// Human-readable reasons for each canonical label.
const LABEL_REASONS = {
  'legitimate_email': 'Content appears legitimate',
  'phishing_email': 'Content matches phishing patterns',
  'legitimate_url': 'Links appear safe',
  'phishing_url': 'Suspicious links detected'
};

// State
let classifier = null;
let modelLoaded = false;
let loadAttempts = 0;
const MAX_LOAD_ATTEMPTS = 3;

// Guards the single in-flight inference: timeout, supersession, and the
// request id used to drop stale results.
const guard = createInferenceGuard();

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

      reportProgress(80, 'Warming up model...');

      // Warm up with dummy inference
      await classifier('Test email for warmup');

      reportProgress(100, 'Model ready');
      modelLoaded = true;

      // Notify background
      chrome.runtime.sendMessage({ type: 'OFFSCREEN_READY' });
      logger.debug('Model loaded successfully');
      return;

    } catch (error) {
      logger.error(`Model load attempt ${loadAttempts} failed:`, error);
      
      if (loadAttempts >= MAX_LOAD_ATTEMPTS) {
        logger.error('All model load attempts failed');
        chrome.runtime.sendMessage({
          type: 'OFFSCREEN_ERROR',
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
  chrome.runtime.sendMessage({
    type: 'MODEL_LOAD_PROGRESS',
    progress,
    message
  }).catch(() => {});
}

/**
 * Run inference on email text with timeout protection.
 *
 * Only one run is in flight at a time. A second request supersedes the first,
 * so a slow scan cannot overlap a newer one and two results cannot race to the
 * same caller.
 */
async function runInference(text, settings = {}, requestId = null) {
  if (!classifier || !modelLoaded) {
    throw new Error('Model not loaded');
  }

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
    // onto our four canonical names.
    const predictions = normalizePredictions(results);

    const topPrediction = predictions[0];
    const label = topPrediction?.label || 'uncertain';
    const confidence = topPrediction?.score || 0;

    // Generate reasons based on predictions
    const reasons = generateReasons(predictions, text, settings);

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
 * Generate human-readable reasons
 */
function generateReasons(predictions, text = '', settings = {}) {
  const reasons = [];

  // Top prediction reason
  const topLabel = predictions[0]?.label;
  if (topLabel && LABEL_REASONS[topLabel]) {
    reasons.push(LABEL_REASONS[topLabel]);
  }

  // Sensitivity threshold check
  const threshold = settings.sensitivityThreshold ?? 0.7;
  if (predictions[0]?.score < threshold) {
    reasons.push('Low confidence - manual review recommended');
  }

  // Check for phishing keywords
  const phishingKeywords = [
    'urgent', 'immediate', 'verify', 'account', 'suspend', 'locked',
    'click here', 'confirm', 'update', 'security', 'unauthorized',
    'limited time', 'act now', 'expire', 'password', 'credential'
  ];

  const lowerText = text.toLowerCase();
  const foundKeywords = phishingKeywords.filter(kw => lowerText.includes(kw));

  if (foundKeywords.length > 0) {
    reasons.push(`Contains urgency keywords: ${foundKeywords.slice(0, 3).join(', ')}`);
  }

  // Check for suspicious links
  const urlRegex = /https?:\/\/[^\s"'<>]+/g;
  const urls = text.match(urlRegex) || [];

  let suspiciousLinks = 0;
  for (const url of urls) {
    if (isUrlSuspicious(url)) suspiciousLinks++;
  }

  if (suspiciousLinks > 0) {
    reasons.push(`${suspiciousLinks} suspicious link(s) detected`);
  }

  // Sender domain analysis + v1.1 brand-lookalike detection
  const emailRegex = /[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  let match;
  while ((match = emailRegex.exec(text)) !== null) {
    const domain = match[1]?.toLowerCase();
    if (!domain) continue;
    if (isDomainSuspicious(domain)) {
      reasons.push(`Suspicious sender domain: ${domain}`);
      break;
    }
    const lookalike = checkLookalikeBrand(domain);
    if (lookalike && lookalike.brand && lookalike.brand !== 'unknown') {
      reasons.push(`Domain mimics "${lookalike.brand}" (${domain})`);
      break;
    }
  }

  return reasons.slice(0, 5);
}

/**
 * Handle messages from background
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return;

  switch (message.type) {
    case 'RUN_INFERENCE':
      runInference(message.payload?.text || '', message.settings || {}, message.requestId)
        .then(result => {
          // A result for a superseded run is dropped here as well as inside
          // runInference: the caller may have moved on since, and answering it
          // would overwrite a newer scan's verdict.
          if (!isLiveRequest(message.requestId)) return;
          requestRuns.delete(message.requestId);
          chrome.runtime.sendMessage({
            type: 'INFERENCE_RESULT',
            requestId: message.requestId,
            result
          }).catch(() => {});
        })
        .catch(error => {
          requestRuns.delete(message.requestId);
          chrome.runtime.sendMessage({
            type: 'INFERENCE_ERROR',
            requestId: message.requestId,
            error: error.message
          }).catch(() => {});
        });
      sendResponse({ success: true });
      return true;
    default:
      // No other type is handled here. Returning true unconditionally used to
      // keep the channel open with no response, which the caller would hang on.
      sendResponse({ success: false, error: `Unsupported message type: ${message.type}` });
      return false;
  }
});

// Initialize on load
init();
