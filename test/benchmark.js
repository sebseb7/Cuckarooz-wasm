import { strict as assert } from 'node:assert';
import { performance } from 'node:perf_hooks';
import {
  DEFAULT_EDGE_BITS,
  DEFAULT_PROOF_SIZE,
  getSolverMemoryBytes,
  getWasmHeapBytes,
  init,
  mine,
  verify,
} from '../index.js';

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

await init();

const edgeBits = DEFAULT_EDGE_BITS;
const proofSize = DEFAULT_PROOF_SIZE;
const solverMem = await getSolverMemoryBytes(edgeBits);
const trials = Math.max(1, Number(process.env.TRIALS || 3));
const difficulties = [1, 2, 4, 8, 16];

console.log(
  `=== Cuckarooz Benchmark (edgeBits=${edgeBits}, proofSize=${proofSize}, solverMem=${formatBytes(solverMem)}, ${trials} trials/difficulty) ===`
);
console.log(
  'diff | avgNonces | avgMine(ms) | min..max(ms)    | ms/nonce | avgVerify(ms) | solverMem | wasmHeap'
);
console.log(
  '-----+-----------+-------------+-----------------+----------+---------------+-----------+----------'
);

for (const difficulty of difficulties) {
  const mineTimes = [];
  const verifyTimes = [];
  const nonceCounts = [];

  for (let t = 0; t < trials; t++) {
    const challenge = `bench:eb${edgeBits}:ps${proofSize}:d${difficulty}:trial-${t}`;
    const t0 = performance.now();
    const res = await mine(challenge, difficulty, { batchSize: 0 });
    const t1 = performance.now();
    const ver = await verify(challenge, difficulty, res.token);
    const t2 = performance.now();

    assert.equal(ver.valid, true);
    assert.ok(res.difficulty >= difficulty);
    mineTimes.push(t1 - t0);
    verifyTimes.push(t2 - t1);
    nonceCounts.push(res.noncesChecked);
  }

  const avgMine = mineTimes.reduce((a, b) => a + b, 0) / trials;
  const minMine = Math.min(...mineTimes);
  const maxMine = Math.max(...mineTimes);
  const avgVerify = verifyTimes.reduce((a, b) => a + b, 0) / trials;
  const avgNonces = nonceCounts.reduce((a, b) => a + b, 0) / trials;
  const msPerNonce = avgMine / avgNonces;
  const heapBytes = await getWasmHeapBytes();

  console.log(
    `${String(difficulty).padStart(4)} | ` +
      `${avgNonces.toFixed(1).padStart(9)} | ` +
      `${avgMine.toFixed(1).padStart(11)} | ` +
      `${`${minMine.toFixed(0)}..${maxMine.toFixed(0)}`.padStart(15)} | ` +
      `${msPerNonce.toFixed(2).padStart(8)} | ` +
      `${avgVerify.toFixed(3).padStart(13)} | ` +
      `${formatBytes(solverMem).padStart(9)} | ` +
      `${formatBytes(heapBytes).padStart(8)}`
  );
}
