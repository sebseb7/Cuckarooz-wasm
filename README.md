# cuckarooz-wasm

[![npm version](https://img.shields.io/npm/v/cuckarooz-wasm)](https://www.npmjs.com/package/cuckarooz-wasm)

Cuckarooz Cycle proof-of-work WebAssembly library for API throttling in **Node.js** and **browsers**, compiled from C11 with Emscripten inside Docker.

Based on John Tromp's [Cuckarooz Cycle](https://github.com/tromp/cuckoo/tree/master/src/cuckarooz) (BLAKE2b-256 + SipHash-2-4 over a unipartite graph).

## Installation

Available on [npm](https://www.npmjs.com/package/cuckarooz-wasm) with prebuilt WebAssembly binaries (`cuckarooz.wasm` + `cuckarooz.js`) included — installs on any platform without compilers or Docker:

```sh
npm install cuckarooz-wasm
```

### Browser (ESM / Bundlers)

```js
import { mine } from 'cuckarooz-wasm';

// 1. Fetch { challenge, difficulty } from your auth server
const { challenge, difficulty } = await fetch('/api/login/challenge').then((r) => r.json());

// 2. Mine a proof in the browser (yields between nonce batches)
const proof = await mine(challenge, difficulty, {
  onProgress: ({ noncesChecked, elapsedMs }) => {
    console.log(`Checked ${noncesChecked} nonces in ${elapsedMs} ms`);
  },
});

// 3. Submit credentials + proof (either `proof.token` or `{ nonce, edges, hash }`)
await fetch('/api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username,
    password,
    challenge,
    proof: proof.token, // or { nonce: proof.nonce, edges: proof.edges, hash: proof.hash }
  }),
});
```

### Node.js Server (Verification)

In Node.js, `cuckarooz-wasm` automatically resolves `index.node.js`, which runs `mine()` on a `worker_threads` worker so it does not block the event loop, while `verify()` runs directly in WASM in ~0.1 ms.

```js
import { verify } from 'cuckarooz-wasm';

const result = await verify(expectedChallenge, expectedDifficulty, req.body.proof);
if (!result.valid) {
  return res.status(429).json({ error: result.error, code: result.code });
}

// Mark challenge as spent (single-use) and proceed to password check
```

## API

- `mine(challenge, difficulty, options?)`: Finds a valid Cuckarooz cycle meeting `difficulty` and returns `{ hash, nonce, edges, difficulty, targetDifficulty, challenge, edgeBits, proofSize, noncesChecked, token }`.
  - `options.edgeBits` (default `18`, range `8..24`): Graph size (`2^edgeBits` edges). `18` uses ~5.2 MiB solver RAM.
  - `options.proofSize` (default `42`, even `4..64`): Cycle length to find.
  - `options.startNonce` (default `0`): Starting nonce (`number | bigint`).
  - `options.maxNonces` (default `1_000_000`): Maximum nonces to search.
  - `options.batchSize` (default `8`): Nonces per async tick in-thread (`0` or `Infinity` disables yielding).
  - `options.signal`: Optional `AbortSignal`.
  - `options.onProgress`: Callback receiving `{ noncesChecked, cyclesFound, elapsedMs }`.
- `verify(challenge, difficulty, proof, options?)`: Verifies a `MiningResult`, `{ nonce, edges, hash? }`, or compact `token` string against `(challenge, difficulty)`. Always enforces server `options.edgeBits` (default `18`) and `options.proofSize` (default `42`) to prevent parameter-downgrade attacks.
- `verifyCycle(header, edges, edgeBits?, proofSize?)`: Low-level Cuckarooz cycle check over a raw header buffer (`0` = `POW_OK`).
- `cycleHash(edges, edgeBits?)`: Returns the 32-byte reversed BLAKE2b cycle hash (`Uint8Array`).
- `getDifficultyFromHash(hash)`: Computes difficulty `floor((2^256 - 1) / hash_be)` from a 32-byte `Uint8Array` or 64-char hex string.
- `encodeToken(proof)` / `decodeToken(token)`: Serialize/deserialize compact base64url proof tokens.

## Building with Emscripten Docker

Requires Docker (`emscripten/emsdk` image):

```sh
npm run build
npm test
```

This runs `docker build -o . .` using `Dockerfile` and outputs `cuckarooz.js` and `cuckarooz.wasm` at the package root.

