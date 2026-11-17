import createCuckooModule from './cuckarooz.js';
import {
  DEFAULT_EDGE_BITS,
  DEFAULT_PROOF_SIZE,
  ERROR_MESSAGES,
  VerifyCode,
  createCuckooAPI,
  decodeToken,
  encodeToken,
  getDifficultyFromHash,
} from './adapter.js';

let apiPromise;

function getAPI() {
  if (!apiPromise) {
    apiPromise = createCuckooModule()
      .then((Module) => createCuckooAPI(Module))
      .catch((error) => {
        apiPromise = undefined;
        throw error;
      });
  }
  return apiPromise;
}

export async function init() {
  await getAPI();
}

export async function mine(challenge, difficulty, options) {
  const api = await getAPI();
  return api.mine(challenge, difficulty, options);
}

export async function verify(challenge, difficulty, proof, options) {
  const api = await getAPI();
  return api.verify(challenge, difficulty, proof, options);
}

export async function verifyCycle(header, edges, edgeBits, proofSize) {
  const api = await getAPI();
  return api.verifyCycle(header, edges, edgeBits, proofSize);
}

export async function cycleHash(edges, edgeBits) {
  const api = await getAPI();
  return api.cycleHash(edges, edgeBits);
}

export async function getSolverMemoryBytes(edgeBits) {
  const api = await getAPI();
  return api.getSolverMemoryBytes(edgeBits);
}

export async function getWasmHeapBytes() {
  const api = await getAPI();
  return api.getWasmHeapBytes();
}

export {
  DEFAULT_EDGE_BITS,
  DEFAULT_PROOF_SIZE,
  ERROR_MESSAGES,
  VerifyCode,
  createCuckooAPI,
  decodeToken,
  encodeToken,
  getDifficultyFromHash,
};
export default mine;
