import { strict as assert } from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import {
  DEFAULT_EDGE_BITS,
  DEFAULT_PROOF_SIZE,
  VerifyCode,
  cycleHash,
  decodeToken,
  encodeToken,
  getDifficultyFromHash,
  getSolverMemoryBytes,
  mine,
  verify,
  verifyCycle,
} from '../index.node.js';
import {
  getWasmHeapBytes,
  mine as browserMine,
  verify as browserVerify,
} from '../index.js';

if (!existsSync(new URL('../cuckarooz.wasm', import.meta.url))) {
  console.error('Missing cuckarooz.wasm — run `npm run build` first.');
  process.exit(2);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

// 1. Default parameters roundtrip via Node worker entry (edgeBits=18, proofSize=42)
{
  const challenge = 'login:alice@example.com:1700000000:salt';
  const result = await mine(challenge, 1);

  assert.equal(result.challenge, challenge);
  assert.equal(result.edgeBits, DEFAULT_EDGE_BITS);
  assert.equal(result.proofSize, DEFAULT_PROOF_SIZE);
  assert.equal(result.edges.length, DEFAULT_PROOF_SIZE);
  assert.match(result.hash, /^[0-9a-f]{64}$/);
  assert.ok(result.difficulty >= 1);
  assert.ok(typeof result.token === 'string' && result.token.length > 20);

  const v1 = await verify(challenge, 1, result);
  assert.equal(v1.valid, true);
  assert.equal(v1.code, VerifyCode.POW_OK);
  assert.equal(v1.hash, result.hash);

  const v2 = await verify(challenge, 1, result.token);
  assert.equal(v2.valid, true);
  assert.equal(v2.hash, result.hash);

  const v3 = await verify(challenge, 1, { nonce: result.nonce, edges: result.edges });
  assert.equal(v3.valid, true);
  assert.equal(v3.hash, result.hash);
  console.log(`default roundtrip (eb=${result.edgeBits}, L=${result.proofSize}, ${result.noncesChecked} nonces, diff=${result.difficulty}): OK`);
}

// 2. Solver memory query & parameter checks
{
  const mem18 = await getSolverMemoryBytes(18);
  const mem22 = await getSolverMemoryBytes(22);
  const mem24 = await getSolverMemoryBytes(24);
  assert.ok(mem18 > 0 && mem22 > mem18 && mem24 > mem22);

  for (const [edgeBits, proofSize] of [
    [14, 12],
    [16, 20],
    [18, 42],
  ]) {
    const challenge = `param-check:${edgeBits}:${proofSize}`;
    const res = await browserMine(challenge, 1, { edgeBits, proofSize, batchSize: 0 });
    const ver = await browserVerify(challenge, 1, res.token, { edgeBits, proofSize });
    assert.equal(ver.valid, true);
    assert.equal(res.edges.length, proofSize);
  }
  console.log(
    `parameter & memory checks (eb18=${formatBytes(mem18)}, eb22=${formatBytes(mem22)}, eb24=${formatBytes(mem24)}, heap=${formatBytes(await getWasmHeapBytes())}): OK`
  );
}

// 3. Browser ESM entry (index.js) with progress callback and binary challenge
{
  const challenge = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
  const progress = [];
  const result = await browserMine(challenge, 2, {
    edgeBits: 14,
    proofSize: 16,
    batchSize: 4,
    onProgress: (info) => progress.push(info),
  });
  assert.ok(progress.length >= 1);
  const verified = await browserVerify(challenge, 2, result.token, {
    edgeBits: 14,
    proofSize: 16,
  });
  assert.equal(verified.valid, true);
  assert.equal(verified.hash, result.hash);
  console.log('browser ESM entry + progress callback: OK');
}

// 4. Token encode/decode roundtrip
{
  const result = await mine('token-roundtrip', 1, { edgeBits: 14, proofSize: 20 });
  const decoded = decodeToken(result.token);
  assert.ok(decoded !== null);
  assert.equal(decoded.version, 1);
  assert.equal(decoded.edgeBits, 14);
  assert.equal(decoded.proofSize, 20);
  assert.equal(decoded.nonce, result.nonce);
  assert.deepEqual(decoded.edges, result.edges);
  assert.equal(decoded.hash, result.hash);
  assert.equal(encodeToken(decoded), result.token);
  assert.equal(decodeToken('invalid-token!!!'), null);
  console.log('token encode/decode: OK');
}

// 5. Security & tamper checks
{
  const challenge = 'auth-challenge-xyz';
  const result = await mine(challenge, 1, { edgeBits: 14, proofSize: 16 });

  const badChallenge = await verify('auth-challenge-other', 1, result, {
    edgeBits: 14,
    proofSize: 16,
  });
  assert.equal(badChallenge.valid, false);
  assert.notEqual(badChallenge.code, VerifyCode.POW_OK);

  const badNonce = await verify(
    challenge,
    1,
    { nonce: Number(result.nonce) + 1, edges: result.edges },
    { edgeBits: 14, proofSize: 16 }
  );
  assert.equal(badNonce.valid, false);

  const swapped = [...result.edges];
  [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
  const badOrder = await verify(
    challenge,
    1,
    { nonce: result.nonce, edges: swapped },
    { edgeBits: 14, proofSize: 16 }
  );
  assert.equal(badOrder.valid, false);
  assert.equal(badOrder.code, VerifyCode.POW_TOO_SMALL);

  const big = [...result.edges];
  big[big.length - 1] = 1 << 14;
  const badBig = await verify(
    challenge,
    1,
    { nonce: result.nonce, edges: big },
    { edgeBits: 14, proofSize: 16 }
  );
  assert.equal(badBig.valid, false);
  assert.equal(badBig.code, VerifyCode.POW_TOO_BIG);

  const tamperedHash = (result.hash[0] === '0' ? '1' : '0') + result.hash.slice(1);
  const badHash = await verify(
    challenge,
    1,
    { nonce: result.nonce, edges: result.edges, hash: tamperedHash },
    { edgeBits: 14, proofSize: 16 }
  );
  assert.equal(badHash.valid, false);
  assert.equal(badHash.code, VerifyCode.POW_HASH_MISMATCH);

  const lowDiff = await verify(challenge, result.difficulty + 100, result, {
    edgeBits: 14,
    proofSize: 16,
  });
  assert.equal(lowDiff.valid, false);
  assert.equal(lowDiff.code, VerifyCode.POW_DIFFICULTY_TOO_LOW);

  const downgrade = await verify(challenge, 1, result.token, {
    edgeBits: 16,
    proofSize: 16,
  });
  assert.equal(downgrade.valid, false);
  assert.equal(downgrade.code, VerifyCode.POW_INVALID_PARAMS);
  console.log('tamper & downgrade checks: OK');
}

// 6. Low-level verifyCycle, cycleHash, getDifficultyFromHash
{
  const challenge = 'low-level-check';
  const result = await mine(challenge, 1, { edgeBits: 14, proofSize: 20 });

  const challengeBytes = new TextEncoder().encode(challenge);
  const header = new Uint8Array(challengeBytes.length + 8);
  header.set(challengeBytes, 0);
  new DataView(header.buffer).setBigUint64(challengeBytes.length, BigInt(result.nonce), true);

  assert.equal(await verifyCycle(header, result.edges, 14, 20), VerifyCode.POW_OK);

  const rawHash = await cycleHash(result.edges, 14);
  assert.equal(rawHash.length, 32);
  const hexHash = Array.from(rawHash, (b) => b.toString(16).padStart(2, '0')).join('');
  assert.equal(hexHash, result.hash);
  assert.equal(getDifficultyFromHash(rawHash), result.difficulty);
  assert.equal(getDifficultyFromHash(hexHash), result.difficulty);
  console.log('low-level verifyCycle/cycleHash/getDifficultyFromHash: OK');
}

// 7. AbortSignal & maxNonces
{
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    () => mine('abort-test', 1, { signal: controller.signal }),
    (err) => err.name === 'AbortError'
  );
  await assert.rejects(
    () => mine('exhaust-test', 1_000_000_000, { edgeBits: 12, proofSize: 20, maxNonces: 3 }),
    /No proof found within maxNonces=3/
  );
  console.log('AbortSignal & maxNonces: OK');
}

// 8. Browser bundle safety check (index.js & adapter.js have no Node-only globals)
{
  for (const file of ['index.js', 'adapter.js']) {
    const src = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
    assert.equal(/\bnode:/.test(src), false, `${file} must not import node: modules`);
    assert.equal(/\brequire\(/.test(src), false, `${file} must not call require()`);
    assert.equal(/\bBuffer\b/.test(src), false, `${file} must not depend on Node Buffer`);
  }
  console.log('browser compatibility check: OK');
}

console.log('\nAll cuckarooz-wasm tests passed.');
