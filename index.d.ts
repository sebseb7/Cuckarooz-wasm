export declare const DEFAULT_EDGE_BITS: number;
export declare const DEFAULT_PROOF_SIZE: number;

export declare const VerifyCode: Readonly<{
  POW_OK: 0;
  POW_HEADER_LENGTH: 1;
  POW_TOO_BIG: 2;
  POW_TOO_SMALL: 3;
  POW_NON_MATCHING: 4;
  POW_BRANCH: 5;
  POW_DEAD_END: 6;
  POW_SHORT_CYCLE: 7;
  POW_UNBALANCED: 8;
  POW_DIFFICULTY_TOO_LOW: 9;
  POW_HASH_MISMATCH: 10;
  POW_INVALID_PARAMS: 11;
}>;

export declare const ERROR_MESSAGES: Readonly<Record<number, string>>;

export type BytesInput = string | Uint8Array | ArrayBuffer | ArrayBufferView;

export interface MineOptions {
  /** Graph size parameter (`2^edgeBits` edges, default 18). Allowed: 8..24. */
  edgeBits?: number;
  /** Cycle length (even integer, default 42). Allowed: 4..64. */
  proofSize?: number;
  /** Initial nonce (default 0). */
  startNonce?: number | bigint;
  /** Maximum nonces to search before rejecting (default 1_000_000). */
  maxNonces?: number;
  /** Nonces per async batch before yielding to the event loop (default 8; 0 or Infinity disables yielding). */
  batchSize?: number;
  /** Optional AbortSignal to cancel mining. */
  signal?: AbortSignal;
  /** Optional progress callback invoked after each batch. */
  onProgress?: (info: { noncesChecked: number; cyclesFound: number; elapsedMs: number }) => void;
}

export interface MiningResult {
  /** 32-byte reversed BLAKE2b cycle hash as a 64-character lowercase hex string. */
  hash: string;
  /** Winning nonce. */
  nonce: number | bigint;
  /** Sorted array of cycle edge indices. */
  edges: number[];
  /** Achieved difficulty of `hash`. */
  difficulty: number;
  /** Target difficulty requested. */
  targetDifficulty: number;
  /** Challenge string (or hex if binary challenge was provided). */
  challenge: string;
  /** Graph size parameter used. */
  edgeBits: number;
  /** Cycle length used. */
  proofSize: number;
  /** Number of nonces evaluated. */
  noncesChecked: number;
  /** Compact base64url proof token encoding nonce, parameters, edges, and hash. */
  token: string;
}

export interface ProofPayload {
  nonce: number | bigint;
  edges: number[] | Uint32Array;
  hash?: string | Uint8Array;
  edgeBits?: number;
  proofSize?: number;
}

export interface VerifyOptions {
  /** Expected graph size parameter (default 18). */
  edgeBits?: number;
  /** Expected cycle length (default 42). */
  proofSize?: number;
}

export interface VerifyResult {
  valid: boolean;
  code: number;
  error?: string;
  hash?: string;
  difficulty?: number;
}

export interface DecodedToken {
  version: number;
  edgeBits: number;
  proofSize: number;
  nonce: number | bigint;
  edges: number[];
  hash: string;
}

export function init(): Promise<void>;

export function mine(
  challenge: BytesInput,
  difficulty: number,
  options?: MineOptions
): Promise<MiningResult>;

export function verify(
  challenge: BytesInput,
  difficulty: number,
  proof: MiningResult | ProofPayload | string,
  options?: VerifyOptions
): Promise<VerifyResult>;

export function verifyCycle(
  header: BytesInput,
  edges: number[] | Uint32Array,
  edgeBits?: number,
  proofSize?: number
): Promise<number>;

export function cycleHash(edges: number[] | Uint32Array, edgeBits?: number): Promise<Uint8Array>;

export function getSolverMemoryBytes(edgeBits?: number): Promise<number>;

export function getWasmHeapBytes(): Promise<number>;

export function getDifficultyFromHash(hash: Uint8Array | string): number;

export function encodeToken(proof: ProofPayload & { hash: string | Uint8Array }): string;

export function decodeToken(token: string): DecodedToken | null;

export function createCuckaroozAPI(Module: unknown): {
  mine(challenge: BytesInput, difficulty: number, options?: MineOptions): Promise<MiningResult>;
  mineSync(challenge: BytesInput, difficulty: number, options?: MineOptions): MiningResult;
  verify(
    challenge: BytesInput,
    difficulty: number,
    proof: MiningResult | ProofPayload | string,
    options?: VerifyOptions
  ): VerifyResult;
  verifySync(
    challenge: BytesInput,
    difficulty: number,
    proof: MiningResult | ProofPayload | string,
    options?: VerifyOptions
  ): VerifyResult;
  verifyCycle(
    header: BytesInput,
    edges: number[] | Uint32Array,
    edgeBits?: number,
    proofSize?: number
  ): number;
  cycleHash(edges: number[] | Uint32Array, edgeBits?: number): Uint8Array;
  getSolverMemoryBytes(edgeBits?: number): number;
  getWasmHeapBytes(): number;
  getDifficultyFromHash: typeof getDifficultyFromHash;
  encodeToken: typeof encodeToken;
  decodeToken: typeof decodeToken;
};

export default mine;
