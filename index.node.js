import {
  DEFAULT_EDGE_BITS,
  DEFAULT_PROOF_SIZE,
  ERROR_MESSAGES,
  VerifyCode,
  createCuckaroozAPI,
  cycleHash,
  decodeToken,
  encodeToken,
  getDifficultyFromHash,
  getSolverMemoryBytes,
  getWasmHeapBytes,
  init,
  mine as mineInThread,
  verify as verifyInThread,
  verifyCycle,
} from './index.js';
import { runInWorker } from './node-worker-client.js';

/**
 * Mines a Cuckarooz proof-of-work solution in a Node.js worker thread
 * so WASM mining does not block the main event loop.
 * When `onProgress` or `signal` is provided, runs with chunked yielding in-thread
 * or rejects on abort.
 */
export async function mine(challenge, difficulty, options = {}) {
  if (options?.signal?.aborted) {
    const err = new Error('Mining aborted');
    err.name = 'AbortError';
    throw err;
  }
  if (typeof options?.onProgress === 'function' || options?.signal) {
    return mineInThread(challenge, difficulty, options);
  }
  return runInWorker('mine', { challenge, difficulty, options });
}

/**
 * Verifies a Cuckarooz proof-of-work solution against `(challenge, difficulty)`.
 * Verification is sub-millisecond and runs directly in the WASM module.
 */
export function verify(challenge, difficulty, proof, options = {}) {
  return verifyInThread(challenge, difficulty, proof, options);
}

export {
  DEFAULT_EDGE_BITS,
  DEFAULT_PROOF_SIZE,
  ERROR_MESSAGES,
  VerifyCode,
  createCuckaroozAPI,
  cycleHash,
  decodeToken,
  encodeToken,
  getDifficultyFromHash,
  getSolverMemoryBytes,
  getWasmHeapBytes,
  init,
  mineInThread,
  verifyCycle,
  verifyInThread,
};
export default mine;
