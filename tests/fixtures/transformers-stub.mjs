/**
 * Stand-in for vendor/transformers.min.js.
 *
 * The real bundle is ~50MB of WASM and cannot run under Node. This stub resolves
 * the warmup call the worker makes on boot, so the model reports ready, and then
 * hangs on every real inference — which is what exercises the timeout.
 */
export const env = {
  allowLocalModels: false,
  allowRemoteModels: true,
  useBrowserCache: false,
  backends: { onnx: { wasm: { wasmPaths: '', numThreads: 1 } } }
};

export async function pipeline() {
  return async (text) => {
    if (text === 'warmup test email') {
      return [{ label: 'LABEL_0', score: 0.5 }];
    }
    // Never resolves: models that hang must not hang the caller.
    return new Promise(() => {});
  };
}