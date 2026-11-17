import { Worker } from 'node:worker_threads';

let worker;
let nextRequestId = 1;
const pending = new Map();

const ERROR_TYPES = { Error, RangeError, TypeError, SyntaxError, URIError, ReferenceError, EvalError };

function deserializeError(serialized) {
  const Constructor = ERROR_TYPES[serialized.name] || Error;
  const error = new Constructor(serialized.message);
  if (serialized.stack) error.stack = serialized.stack;
  if (serialized.status !== undefined) error.status = serialized.status;
  return error;
}

function rejectAll(error) {
  for (const { reject } of pending.values()) reject(error);
  pending.clear();
}

function getWorker() {
  if (worker) return worker;

  worker = new Worker(new URL('./node-worker.js', import.meta.url));
  worker.unref();

  worker.on('message', ({ id, result, error }) => {
    const request = pending.get(id);
    if (!request) return;

    pending.delete(id);
    if (pending.size === 0) worker?.unref();

    if (error) request.reject(deserializeError(error));
    else request.resolve(result);
  });

  worker.on('error', (error) => {
    rejectAll(error);
  });

  worker.on('exit', (code) => {
    const exitedWorker = worker;
    worker = undefined;
    if (pending.size > 0) {
      rejectAll(new Error(`cuckoo-wasm worker stopped unexpectedly with exit code ${code}`));
    }
    exitedWorker?.removeAllListeners();
  });

  return worker;
}

function copyBytesIfTyped(value) {
  if (value instanceof Uint8Array) return value.slice();
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  }
  return value;
}

export function runInWorker(operation, payload) {
  const w = getWorker();
  w.ref();
  const id = nextRequestId++;
  const cloned = {
    ...payload,
    challenge: copyBytesIfTyped(payload.challenge),
  };
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    w.postMessage({ id, operation, payload: cloned });
  });
}
