import { parentPort } from 'node:worker_threads';
import { mine, verify } from './index.js';

function serializeError(error) {
  return {
    name: error?.name || 'Error',
    message: error?.message || String(error),
    stack: error?.stack,
    status: error?.status,
  };
}

parentPort.on('message', async ({ id, operation, payload }) => {
  try {
    let result;
    if (operation === 'mine') {
      result = await mine(payload.challenge, payload.difficulty, payload.options);
    } else if (operation === 'verify') {
      result = await verify(payload.challenge, payload.difficulty, payload.proof, payload.options);
    } else {
      throw new TypeError(`Unknown cuckoo-wasm operation: ${operation}`);
    }

    parentPort.postMessage({ id, result });
  } catch (error) {
    parentPort.postMessage({ id, error: serializeError(error) });
  }
});
