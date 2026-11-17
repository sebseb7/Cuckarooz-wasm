/**
 * Adapter for the Emscripten Cuckarooz WASM module built via `npm run build` (see Dockerfile).
 * All returned arrays and typed arrays are copies, independent of WASM memory growth/free.
 */

export const DEFAULT_EDGE_BITS = 18;
export const DEFAULT_PROOF_SIZE = 42;

export const VerifyCode = Object.freeze({
  POW_OK: 0,
  POW_HEADER_LENGTH: 1,
  POW_TOO_BIG: 2,
  POW_TOO_SMALL: 3,
  POW_NON_MATCHING: 4,
  POW_BRANCH: 5,
  POW_DEAD_END: 6,
  POW_SHORT_CYCLE: 7,
  POW_UNBALANCED: 8,
  POW_DIFFICULTY_TOO_LOW: 9,
  POW_HASH_MISMATCH: 10,
  POW_INVALID_PARAMS: 11,
});

export const ERROR_MESSAGES = Object.freeze({
  [VerifyCode.POW_OK]: 'OK',
  [VerifyCode.POW_HEADER_LENGTH]: 'wrong header length',
  [VerifyCode.POW_TOO_BIG]: 'edge too big',
  [VerifyCode.POW_TOO_SMALL]: 'edges not ascending',
  [VerifyCode.POW_NON_MATCHING]: 'endpoints do not match up',
  [VerifyCode.POW_BRANCH]: 'branch in cycle',
  [VerifyCode.POW_DEAD_END]: 'cycle dead ends',
  [VerifyCode.POW_SHORT_CYCLE]: 'cycle too short',
  [VerifyCode.POW_UNBALANCED]: 'edges not balanced',
  [VerifyCode.POW_DIFFICULTY_TOO_LOW]: 'hash does not meet target difficulty',
  [VerifyCode.POW_HASH_MISMATCH]: 'provided hash does not match cycle hash',
  [VerifyCode.POW_INVALID_PARAMS]: 'invalid parameters or proof format',
});

const DIFF1 = (1n << 256n) - 1n;
const TEXT_ENCODER = new TextEncoder();
const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function toBytes(input) {
  if (typeof input === 'string') return TEXT_ENCODER.encode(input);
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new TypeError('Expected string, Uint8Array, or ArrayBuffer');
}

export function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    return null;
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function encodeBase64Url(bytes) {
  let b64;
  if (typeof btoa === 'function') {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    b64 = btoa(bin);
  } else {
    b64 = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const b0 = bytes[i];
      const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
      const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
      const triple = (b0 << 16) | (b1 << 8) | b2;
      b64 += B64_ALPHABET[(triple >> 18) & 0x3f];
      b64 += B64_ALPHABET[(triple >> 12) & 0x3f];
      b64 += i + 1 < bytes.length ? B64_ALPHABET[(triple >> 6) & 0x3f] : '';
      b64 += i + 2 < bytes.length ? B64_ALPHABET[triple & 0x3f] : '';
    }
  }
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64Url(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]+$/.test(str)) {
    return null;
  }
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  if (typeof atob === 'function') {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  const clean = padded.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let pos = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = B64_ALPHABET.indexOf(clean[i]);
    const c1 = B64_ALPHABET.indexOf(clean[i + 1]);
    const c2 = i + 2 < clean.length ? B64_ALPHABET.indexOf(clean[i + 2]) : 0;
    const c3 = i + 3 < clean.length ? B64_ALPHABET.indexOf(clean[i + 3]) : 0;
    const triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    out[pos++] = (triple >> 16) & 0xff;
    if (i + 2 < clean.length) out[pos++] = (triple >> 8) & 0xff;
    if (i + 3 < clean.length) out[pos++] = triple & 0xff;
  }
  return out;
}

function splitU64(value) {
  const n = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
  if (n < 0n || n > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError('Nonce must be an unsigned 64-bit integer');
  }
  return [Number(n & 0xffff_ffffn), Number((n >> 32n) & 0xffff_ffffn)];
}

function joinU64(lo, hi) {
  const big = (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0);
  return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
}

export function getDifficultyFromHash(hash) {
  const bytes = typeof hash === 'string' ? hexToBytes(hash) : toBytes(hash);
  if (!bytes || bytes.length !== 32) {
    throw new TypeError('Hash must be 32 bytes or a 64-character hex string');
  }
  const rev = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    rev[i] = bytes[31 - i];
  }
  const hashNum = BigInt('0x' + bytesToHex(rev));
  if (hashNum === 0n) {
    return Infinity;
  }
  return Number(DIFF1 / hashNum);
}

export function encodeToken(proof) {
  const edgeBits = proof.edgeBits ?? DEFAULT_EDGE_BITS;
  const proofSize = proof.proofSize ?? proof.edges?.length;
  if (!proof || !Array.isArray(proof.edges) || proof.edges.length !== proofSize) {
    throw new TypeError('Invalid proof object for token encoding');
  }
  const hashBytes = typeof proof.hash === 'string' ? hexToBytes(proof.hash) : toBytes(proof.hash);
  if (!hashBytes || hashBytes.length !== 32) {
    throw new TypeError('Proof hash must be 32 bytes or 64-char hex');
  }

  const packedBytes = Math.ceil((proofSize * edgeBits) / 8);
  const out = new Uint8Array(11 + packedBytes + 32);
  out[0] = 1;
  out[1] = edgeBits & 0xff;
  out[2] = proofSize & 0xff;

  const [lo, hi] = splitU64(proof.nonce);
  const view = new DataView(out.buffer);
  view.setUint32(3, lo, true);
  view.setUint32(7, hi, true);

  let bytePos = 11;
  let bitPos = 0;
  for (let i = 0; i < proofSize; i++) {
    const edge = proof.edges[i] >>> 0;
    for (let b = 0; b < edgeBits; b++) {
      if ((edge >>> b) & 1) {
        out[bytePos] |= 1 << bitPos;
      }
      bitPos++;
      if (bitPos === 8) {
        bitPos = 0;
        bytePos++;
      }
    }
  }

  out.set(hashBytes, 11 + packedBytes);
  return encodeBase64Url(out);
}

export function decodeToken(token) {
  const bytes = decodeBase64Url(token);
  if (!bytes || bytes.length < 11 + 32 || bytes[0] !== 1) {
    return null;
  }
  const edgeBits = bytes[1];
  const proofSize = bytes[2];
  if (edgeBits < 8 || edgeBits > 29 || proofSize < 4 || proofSize > 64 || proofSize % 2 !== 0) {
    return null;
  }
  const packedBytes = Math.ceil((proofSize * edgeBits) / 8);
  if (bytes.length !== 11 + packedBytes + 32) {
    return null;
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const nonce = joinU64(view.getUint32(3, true), view.getUint32(7, true));

  const edges = new Array(proofSize);
  let bytePos = 11;
  let bitPos = 0;
  for (let i = 0; i < proofSize; i++) {
    let edge = 0;
    for (let b = 0; b < edgeBits; b++) {
      if ((bytes[bytePos] >> bitPos) & 1) {
        edge |= 1 << b;
      }
      bitPos++;
      if (bitPos === 8) {
        bitPos = 0;
        bytePos++;
      }
    }
    edges[i] = edge >>> 0;
  }

  const hashBytes = bytes.slice(11 + packedBytes);
  return {
    version: 1,
    edgeBits,
    proofSize,
    nonce,
    edges,
    hash: bytesToHex(hashBytes),
  };
}

function normalizeMineOptions(difficulty, options = {}) {
  if (typeof difficulty !== 'number' || !Number.isFinite(difficulty) || difficulty < 1) {
    throw new RangeError('difficulty must be a finite number >= 1');
  }
  const edgeBits = options.edgeBits ?? DEFAULT_EDGE_BITS;
  const proofSize = options.proofSize ?? DEFAULT_PROOF_SIZE;
  const startNonce = options.startNonce ?? 0;
  const maxNonces = options.maxNonces ?? 1_000_000;
  const batchSize = options.batchSize ?? 8;

  if (!Number.isInteger(edgeBits) || edgeBits < 8 || edgeBits > 24) {
    throw new RangeError('edgeBits must be an integer between 8 and 24');
  }
  if (!Number.isInteger(proofSize) || proofSize < 4 || proofSize > 64 || proofSize % 2 !== 0) {
    throw new RangeError('proofSize must be an even integer between 4 and 64');
  }
  if (!Number.isInteger(maxNonces) || maxNonces < 1) {
    throw new RangeError('maxNonces must be a positive integer');
  }
  return { edgeBits, proofSize, startNonce, maxNonces, batchSize };
}

function buildMiningResult({
  challenge,
  difficulty,
  edgeBits,
  proofSize,
  nonce,
  edges,
  revHash,
  noncesChecked,
}) {
  const hash = bytesToHex(revHash);
  const achievedDifficulty = getDifficultyFromHash(revHash);
  const challengeStr = typeof challenge === 'string' ? challenge : bytesToHex(toBytes(challenge));
  const result = {
    hash,
    nonce,
    edges,
    difficulty: achievedDifficulty,
    targetDifficulty: difficulty,
    challenge: challengeStr,
    edgeBits,
    proofSize,
    noncesChecked,
    token: '',
  };
  result.token = encodeToken(result);
  return result;
}

function parseProofInput(proof, expectedEdgeBits, expectedProofSize) {
  let parsed = proof;
  if (typeof proof === 'string') {
    parsed = decodeToken(proof);
    if (!parsed) return { errorCode: VerifyCode.POW_INVALID_PARAMS };
  }
  if (!parsed || typeof parsed !== 'object') {
    return { errorCode: VerifyCode.POW_INVALID_PARAMS };
  }
  if (parsed.edgeBits !== undefined && parsed.edgeBits !== expectedEdgeBits) {
    return { errorCode: VerifyCode.POW_INVALID_PARAMS };
  }
  if (parsed.proofSize !== undefined && parsed.proofSize !== expectedProofSize) {
    return { errorCode: VerifyCode.POW_INVALID_PARAMS };
  }

  const { nonce, edges, hash } = parsed;
  if (
    (typeof nonce !== 'number' && typeof nonce !== 'bigint') ||
    (typeof nonce === 'number' && (!Number.isInteger(nonce) || nonce < 0)) ||
    (typeof nonce === 'bigint' && nonce < 0n)
  ) {
    return { errorCode: VerifyCode.POW_INVALID_PARAMS };
  }
  if (!edges || typeof edges.length !== 'number' || edges.length !== expectedProofSize) {
    return { errorCode: VerifyCode.POW_INVALID_PARAMS };
  }
  for (let i = 0; i < edges.length; i++) {
    const e = edges[i];
    if (!Number.isInteger(e) || e < 0 || e > 0xffff_ffff) {
      return { errorCode: VerifyCode.POW_INVALID_PARAMS };
    }
  }

  let expectedHashBytes = null;
  if (hash !== undefined && hash !== null) {
    expectedHashBytes = typeof hash === 'string' ? hexToBytes(hash) : toBytes(hash);
    if (!expectedHashBytes || expectedHashBytes.length !== 32) {
      return { errorCode: VerifyCode.POW_INVALID_PARAMS };
    }
  }

  return { nonce, edges, expectedHashBytes };
}

export function createCuckooAPI(Module) {
  function allocBytes(bytes) {
    if (bytes.length === 0) return 0;
    const ptr = Module._malloc(bytes.length);
    if (!ptr) throw new Error('cuckoo-wasm: out of memory');
    Module.HEAPU8.set(bytes, ptr);
    return ptr;
  }

  function allocU32(values) {
    const byteLen = values.length * 4;
    if (byteLen === 0) return 0;
    const ptr = Module._malloc(byteLen);
    if (!ptr) throw new Error('cuckoo-wasm: out of memory');
    const offset = ptr >>> 2;
    for (let i = 0; i < values.length; i++) {
      Module.HEAPU32[offset + i] = values[i] >>> 0;
    }
    return ptr;
  }

  function freePtr(ptr) {
    if (ptr) Module._free(ptr);
  }

  function verifyCycle(header, edges, edgeBits = 29, proofSize = edges?.length ?? 40) {
    const hdrBytes = toBytes(header);
    if (!edges || typeof edges.length !== 'number' || edges.length !== proofSize) {
      return VerifyCode.POW_INVALID_PARAMS;
    }
    const hdrCopy = Uint8Array.from(hdrBytes);
    const edgesCopy = Array.from(edges);
    let hdrPtr = 0;
    let edgesPtr = 0;
    try {
      hdrPtr = allocBytes(hdrCopy);
      edgesPtr = allocU32(edgesCopy);
      return Module._cz_verify_cycle(hdrPtr, hdrCopy.length, edgesPtr, edgeBits, proofSize);
    } finally {
      freePtr(hdrPtr);
      freePtr(edgesPtr);
    }
  }

  function cycleHash(edges, edgeBits = 29) {
    if (!edges || typeof edges.length !== 'number') {
      throw new TypeError('edges must be an array or TypedArray');
    }
    const edgesCopy = Array.from(edges);
    let edgesPtr = 0;
    let outPtr = 0;
    try {
      edgesPtr = allocU32(edgesCopy);
      outPtr = Module._malloc(32);
      if (!outPtr) throw new Error('cuckoo-wasm: out of memory');
      const rc = Module._cz_cycle_hash(edgesPtr, edgesCopy.length, edgeBits, outPtr);
      if (rc !== VerifyCode.POW_OK) {
        throw new Error(ERROR_MESSAGES[rc] || 'Failed to compute cycle hash');
      }
      return Module.HEAPU8.slice(outPtr, outPtr + 32);
    } finally {
      freePtr(edgesPtr);
      freePtr(outPtr);
    }
  }

  function verify(challenge, difficulty, proof, options = {}) {
    if (typeof difficulty !== 'number' || !Number.isFinite(difficulty) || difficulty < 1) {
      return {
        valid: false,
        code: VerifyCode.POW_INVALID_PARAMS,
        error: ERROR_MESSAGES[VerifyCode.POW_INVALID_PARAMS],
      };
    }

    const expectedEdgeBits = options.edgeBits ?? DEFAULT_EDGE_BITS;
    const expectedProofSize = options.proofSize ?? DEFAULT_PROOF_SIZE;
    const parsed = parseProofInput(proof, expectedEdgeBits, expectedProofSize);
    if (parsed.errorCode !== undefined) {
      return {
        valid: false,
        code: parsed.errorCode,
        error: ERROR_MESSAGES[parsed.errorCode],
      };
    }

    const challengeBytes = Uint8Array.from(toBytes(challenge));
    const [nonceLo, nonceHi] = splitU64(parsed.nonce);
    let challengePtr = 0;
    let edgesPtr = 0;
    let expectedHashPtr = 0;
    let outHashPtr = 0;

    try {
      challengePtr = allocBytes(challengeBytes);
      edgesPtr = allocU32(parsed.edges);
      if (parsed.expectedHashBytes) {
        expectedHashPtr = allocBytes(parsed.expectedHashBytes);
      }
      outHashPtr = Module._malloc(32);
      if (!outHashPtr) throw new Error('cuckoo-wasm: out of memory');

      const code = Module._cz_verify_challenge(
        challengePtr,
        challengeBytes.length,
        nonceLo,
        nonceHi,
        edgesPtr,
        expectedProofSize,
        expectedEdgeBits,
        difficulty,
        expectedHashPtr,
        parsed.expectedHashBytes ? 1 : 0,
        outHashPtr
      );

      if (code === VerifyCode.POW_OK) {
        const revHash = Module.HEAPU8.slice(outHashPtr, outHashPtr + 32);
        return {
          valid: true,
          code,
          hash: bytesToHex(revHash),
          difficulty: getDifficultyFromHash(revHash),
        };
      }

      let hash;
      let achievedDifficulty;
      if (
        code === VerifyCode.POW_DIFFICULTY_TOO_LOW ||
        code === VerifyCode.POW_HASH_MISMATCH
      ) {
        const revHash = Module.HEAPU8.slice(outHashPtr, outHashPtr + 32);
        hash = bytesToHex(revHash);
        achievedDifficulty = getDifficultyFromHash(revHash);
      }

      return {
        valid: false,
        code,
        error: ERROR_MESSAGES[code] || `Verification failed with code ${code}`,
        ...(hash !== undefined ? { hash, difficulty: achievedDifficulty } : {}),
      };
    } finally {
      freePtr(challengePtr);
      freePtr(edgesPtr);
      freePtr(expectedHashPtr);
      freePtr(outHashPtr);
    }
  }

  function mineSync(challenge, difficulty, options = {}) {
    const { edgeBits, proofSize, startNonce, maxNonces } = normalizeMineOptions(difficulty, options);
    const challengeBytes = Uint8Array.from(toBytes(challenge));

    const solverPtr = Module._cz_solver_new(edgeBits);
    if (!solverPtr) {
      throw new Error(`Failed to initialize Cuckarooz solver for edgeBits=${edgeBits}`);
    }

    let challengePtr = 0;
    let outLoPtr = 0;
    let outHiPtr = 0;
    let outEdgesPtr = 0;
    let outHashPtr = 0;
    let outCheckedPtr = 0;
    let outCyclesPtr = 0;

    try {
      challengePtr = allocBytes(challengeBytes);
      outLoPtr = Module._malloc(4);
      outHiPtr = Module._malloc(4);
      outEdgesPtr = Module._malloc(proofSize * 4);
      outHashPtr = Module._malloc(32);
      outCheckedPtr = Module._malloc(4);
      outCyclesPtr = Module._malloc(4);

      const [startLo, startHi] = splitU64(startNonce);
      const status = Module._cz_solver_mine_batch(
        solverPtr,
        challengePtr,
        challengeBytes.length,
        startLo,
        startHi,
        maxNonces >>> 0,
        proofSize,
        difficulty,
        outLoPtr,
        outHiPtr,
        outEdgesPtr,
        outHashPtr,
        outCheckedPtr,
        outCyclesPtr
      );

      if (status === 1) {
        const lo = Module.HEAPU32[outLoPtr >>> 2];
        const hi = Module.HEAPU32[outHiPtr >>> 2];
        const edgesOffset = outEdgesPtr >>> 2;
        const edges = Array.from(Module.HEAPU32.subarray(edgesOffset, edgesOffset + proofSize));
        const revHash = Module.HEAPU8.slice(outHashPtr, outHashPtr + 32);
        const checked = Module.HEAPU32[outCheckedPtr >>> 2];

        return buildMiningResult({
          challenge,
          difficulty,
          edgeBits,
          proofSize,
          nonce: joinU64(lo, hi),
          edges,
          revHash,
          noncesChecked: checked,
        });
      }

      if (status === 0) {
        throw new Error(`No proof found within maxNonces=${maxNonces}`);
      }
      throw new Error(ERROR_MESSAGES[status] || `Mining failed with code ${status}`);
    } finally {
      freePtr(challengePtr);
      freePtr(outLoPtr);
      freePtr(outHiPtr);
      freePtr(outEdgesPtr);
      freePtr(outHashPtr);
      freePtr(outCheckedPtr);
      freePtr(outCyclesPtr);
      Module._cz_solver_free(solverPtr);
    }
  }

  async function mine(challenge, difficulty, options = {}) {
    const { edgeBits, proofSize, startNonce, maxNonces, batchSize } = normalizeMineOptions(
      difficulty,
      options
    );
    const { signal, onProgress } = options;

    if (signal?.aborted) {
      const err = new Error('Mining aborted');
      err.name = 'AbortError';
      throw err;
    }

    const challengeBytes = Uint8Array.from(toBytes(challenge));
    const solverPtr = Module._cz_solver_new(edgeBits);
    if (!solverPtr) {
      throw new Error(`Failed to initialize Cuckarooz solver for edgeBits=${edgeBits}`);
    }

    let challengePtr = 0;
    let outLoPtr = 0;
    let outHiPtr = 0;
    let outEdgesPtr = 0;
    let outHashPtr = 0;
    let outCheckedPtr = 0;
    let outCyclesPtr = 0;

    try {
      challengePtr = allocBytes(challengeBytes);
      outLoPtr = Module._malloc(4);
      outHiPtr = Module._malloc(4);
      outEdgesPtr = Module._malloc(proofSize * 4);
      outHashPtr = Module._malloc(32);
      outCheckedPtr = Module._malloc(4);
      outCyclesPtr = Module._malloc(4);

      const effectiveBatch =
        batchSize <= 0 || !Number.isFinite(batchSize)
          ? maxNonces
          : Math.max(1, Math.trunc(batchSize));
      const startTime = Date.now();
      let totalChecked = 0;
      let totalCycles = 0;
      let currentNonce = typeof startNonce === 'bigint' ? startNonce : BigInt(Math.trunc(startNonce));

      while (totalChecked < maxNonces) {
        if (signal?.aborted) {
          const err = new Error('Mining aborted');
          err.name = 'AbortError';
          throw err;
        }

        const remaining = maxNonces - totalChecked;
        const chunk = Math.min(effectiveBatch, remaining);
        const [lo, hi] = splitU64(currentNonce);

        const status = Module._cz_solver_mine_batch(
          solverPtr,
          challengePtr,
          challengeBytes.length,
          lo,
          hi,
          chunk >>> 0,
          proofSize,
          difficulty,
          outLoPtr,
          outHiPtr,
          outEdgesPtr,
          outHashPtr,
          outCheckedPtr,
          outCyclesPtr
        );

        const checked = Module.HEAPU32[outCheckedPtr >>> 2];
        const cycles = Module.HEAPU32[outCyclesPtr >>> 2];
        totalChecked += checked;
        totalCycles += cycles;

        if (status === 1) {
          const winLo = Module.HEAPU32[outLoPtr >>> 2];
          const winHi = Module.HEAPU32[outHiPtr >>> 2];
          const edgesOffset = outEdgesPtr >>> 2;
          const edges = Array.from(Module.HEAPU32.subarray(edgesOffset, edgesOffset + proofSize));
          const revHash = Module.HEAPU8.slice(outHashPtr, outHashPtr + 32);

          if (typeof onProgress === 'function') {
            onProgress({
              noncesChecked: totalChecked,
              cyclesFound: totalCycles,
              elapsedMs: Date.now() - startTime,
            });
          }

          return buildMiningResult({
            challenge,
            difficulty,
            edgeBits,
            proofSize,
            nonce: joinU64(winLo, winHi),
            edges,
            revHash,
            noncesChecked: totalChecked,
          });
        }

        if (status !== 0) {
          throw new Error(ERROR_MESSAGES[status] || `Mining failed with code ${status}`);
        }

        if (typeof onProgress === 'function') {
          onProgress({
            noncesChecked: totalChecked,
            cyclesFound: totalCycles,
            elapsedMs: Date.now() - startTime,
          });
        }

        currentNonce += BigInt(chunk);
        if (totalChecked < maxNonces && effectiveBatch < maxNonces) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
      }

      throw new Error(`No proof found within maxNonces=${maxNonces}`);
    } finally {
      freePtr(challengePtr);
      freePtr(outLoPtr);
      freePtr(outHiPtr);
      freePtr(outEdgesPtr);
      freePtr(outHashPtr);
      freePtr(outCheckedPtr);
      freePtr(outCyclesPtr);
      Module._cz_solver_free(solverPtr);
    }
  }

  function getSolverMemoryBytes(edgeBits = DEFAULT_EDGE_BITS) {
    if (!Number.isInteger(edgeBits) || edgeBits < 8 || edgeBits > 24) {
      throw new RangeError('edgeBits must be an integer between 8 and 24');
    }
    return Module._cz_solver_memory_bytes(edgeBits) >>> 0;
  }

  function getWasmHeapBytes() {
    return Module.HEAPU8.byteLength;
  }

  return {
    mine,
    mineSync,
    verify,
    verifySync: verify,
    verifyCycle,
    cycleHash,
    getSolverMemoryBytes,
    getWasmHeapBytes,
    getDifficultyFromHash,
    encodeToken,
    decodeToken,
  };
}
