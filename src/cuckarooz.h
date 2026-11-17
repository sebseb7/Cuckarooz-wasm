#ifndef CUCKAROOZ_WASM_H
#define CUCKAROOZ_WASM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum cz_verify_code {
  CZ_POW_OK = 0,
  CZ_POW_HEADER_LENGTH = 1,
  CZ_POW_TOO_BIG = 2,
  CZ_POW_TOO_SMALL = 3,
  CZ_POW_NON_MATCHING = 4,
  CZ_POW_BRANCH = 5,
  CZ_POW_DEAD_END = 6,
  CZ_POW_SHORT_CYCLE = 7,
  CZ_POW_UNBALANCED = 8,
  CZ_POW_DIFFICULTY_TOO_LOW = 9,
  CZ_POW_HASH_MISMATCH = 10,
  CZ_POW_INVALID_PARAMS = 11
};

#define CZ_MIN_EDGE_BITS 8u
#define CZ_MAX_MINE_EDGE_BITS 24u
#define CZ_MAX_VERIFY_EDGE_BITS 29u
#define CZ_MIN_PROOF_SIZE 4u
#define CZ_MAX_PROOF_SIZE 64u

typedef struct cz_solver cz_solver_t;

uint32_t cz_verify_cycle(
    const uint8_t *header,
    size_t header_len,
    const uint32_t *edges,
    uint32_t edge_bits,
    size_t proof_size);

uint32_t cz_cycle_hash(
    const uint32_t *edges,
    size_t proof_size,
    uint32_t edge_bits,
    uint8_t *out_rev_hash);

uint32_t cz_verify_challenge(
    const uint8_t *challenge,
    size_t challenge_len,
    uint32_t nonce_lo,
    uint32_t nonce_hi,
    const uint32_t *edges,
    size_t proof_size,
    uint32_t edge_bits,
    double difficulty,
    const uint8_t *expected_rev_hash,
    uint32_t has_expected_hash,
    uint8_t *out_rev_hash);

cz_solver_t *cz_solver_new(uint32_t edge_bits);
void cz_solver_free(cz_solver_t *solver);
uint32_t cz_solver_memory_bytes(uint32_t edge_bits);

uint32_t cz_solver_mine_batch(
    cz_solver_t *solver,
    const uint8_t *challenge,
    size_t challenge_len,
    uint32_t start_nonce_lo,
    uint32_t start_nonce_hi,
    uint32_t num_nonces,
    size_t proof_size,
    double difficulty,
    uint32_t *out_nonce_lo,
    uint32_t *out_nonce_hi,
    uint32_t *out_edges,
    uint8_t *out_rev_hash,
    uint32_t *out_nonces_checked,
    uint32_t *out_cycles_found);

#ifdef __cplusplus
}
#endif

#endif
