#include "cuckarooz.h"
#include "crypto/blake2.h"

#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define EDGE_BLOCK_BITS 6u
#define EDGE_BLOCK_SIZE (1u << EDGE_BLOCK_BITS)
#define EDGE_BLOCK_MASK (EDGE_BLOCK_SIZE - 1u)
#define CZ_NIL UINT32_MAX

typedef struct {
  uint64_t k0;
  uint64_t k1;
  uint64_t k2;
  uint64_t k3;
} siphash_keys_t;

typedef struct {
  uint64_t v0;
  uint64_t v1;
  uint64_t v2;
  uint64_t v3;
} siphash_state_t;

static inline uint64_t load_le64(const uint8_t *p) {
  return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) |
         ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
         ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
         ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void store_le64(uint8_t *p, uint64_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
  p[4] = (uint8_t)(v >> 32);
  p[5] = (uint8_t)(v >> 40);
  p[6] = (uint8_t)(v >> 48);
  p[7] = (uint8_t)(v >> 56);
}

static inline void store_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v);
}

static inline uint64_t rotl64(uint64_t x, uint32_t b) {
  return (x << b) | (x >> (64u - b));
}

static inline void sip_round(siphash_state_t *s) {
  s->v0 += s->v1;
  s->v2 += s->v3;
  s->v1 = rotl64(s->v1, 13);
  s->v3 = rotl64(s->v3, 16);
  s->v1 ^= s->v0;
  s->v3 ^= s->v2;
  s->v0 = rotl64(s->v0, 32);
  s->v2 += s->v1;
  s->v0 += s->v3;
  s->v1 = rotl64(s->v1, 17);
  s->v3 = rotl64(s->v3, 21);
  s->v1 ^= s->v2;
  s->v3 ^= s->v0;
  s->v2 = rotl64(s->v2, 32);
}

static inline void hash24(siphash_state_t *s, uint64_t nonce) {
  s->v3 ^= nonce;
  sip_round(s);
  sip_round(s);
  s->v0 ^= nonce;
  s->v2 ^= 0xffULL;
  sip_round(s);
  sip_round(s);
  sip_round(s);
  sip_round(s);
}

static inline uint64_t xor_lanes(const siphash_state_t *s) {
  return (s->v0 ^ s->v1) ^ (s->v2 ^ s->v3);
}

static void sipkeys_from_bytes(const uint8_t keybuf[32], siphash_keys_t *keys) {
  keys->k0 = load_le64(keybuf + 0);
  keys->k1 = load_le64(keybuf + 8);
  keys->k2 = load_le64(keybuf + 16);
  keys->k3 = load_le64(keybuf + 24);
}

static void set_header_keys(const uint8_t *header, size_t header_len, siphash_keys_t *keys) {
  uint8_t hdrkey[32];
  blake2b(hdrkey, sizeof(hdrkey), header, header_len, NULL, 0);
  sipkeys_from_bytes(hdrkey, keys);
}

static void set_challenge_nonce_keys(
    const uint8_t *challenge,
    size_t challenge_len,
    uint64_t nonce,
    siphash_keys_t *keys) {
  uint8_t nonce_bytes[8];
  store_le64(nonce_bytes, nonce);

  blake2b_state S;
  blake2b_init(&S, 32);
  if (challenge_len > 0) {
    blake2b_update(&S, challenge, challenge_len);
  }
  blake2b_update(&S, nonce_bytes, sizeof(nonce_bytes));

  uint8_t hdrkey[32];
  blake2b_final(&S, hdrkey, sizeof(hdrkey));
  sipkeys_from_bytes(hdrkey, keys);
}

// Cuckarooz sipblock: computes 64 SipHash-2-4 lanes and applies the backward suffix XOR chain.
static void sipblock_fill(const siphash_keys_t *keys, uint32_t edge0, uint64_t buf[EDGE_BLOCK_SIZE]) {
  siphash_state_t shs = {keys->k0, keys->k1, keys->k2, keys->k3};
  uint32_t base = edge0 & ~EDGE_BLOCK_MASK;
  for (uint32_t i = 0; i < EDGE_BLOCK_SIZE; i++) {
    hash24(&shs, (uint64_t)(base + i));
    buf[i] = xor_lanes(&shs);
  }
  for (uint32_t i = EDGE_BLOCK_MASK; i > 0; i--) {
    buf[i - 1] ^= buf[i];
  }
}

static bool validate_params(uint32_t edge_bits, size_t proof_size, uint32_t max_edge_bits) {
  return edge_bits >= CZ_MIN_EDGE_BITS &&
         edge_bits <= max_edge_bits &&
         proof_size >= CZ_MIN_PROOF_SIZE &&
         proof_size <= CZ_MAX_PROOF_SIZE &&
         (proof_size % 2u) == 0;
}

// 128-bit unsigned integer helpers (portable C11 without __int128 for wasm32)
typedef struct {
  uint64_t hi;
  uint64_t lo;
} u128_t;

static inline bool u128_ge(u128_t a, u128_t b) {
  return (a.hi > b.hi) || (a.hi == b.hi && a.lo >= b.lo);
}

static inline u128_t u128_sub(u128_t a, u128_t b) {
  u128_t r;
  r.lo = a.lo - b.lo;
  r.hi = a.hi - b.hi - (a.lo < b.lo ? 1ULL : 0ULL);
  return r;
}

static u128_t u128_from_double(double v) {
  if (v <= 0.0) {
    return (u128_t){0, 0};
  }
  double two64 = 18446744073709551616.0; // 2^64
  uint64_t hi = (uint64_t)floor(v / two64);
  double rem = v - ((double)hi * two64);
  if (rem < 0.0) {
    rem = 0.0;
  }
  uint64_t lo = (uint64_t)llround(rem);
  return (u128_t){hi, lo};
}

// Computes big-endian 256-bit target hash = floor((2^256 - 1) / difficulty).
static bool target_from_difficulty(double difficulty, uint8_t out_target_be[32]) {
  if (isnan(difficulty) || !isfinite(difficulty) || difficulty <= 0.0) {
    return false;
  }
  if (difficulty <= 1.0) {
    memset(out_target_be, 0xff, 32);
    return true;
  }

  uint64_t scale;
  u128_t denom;
  if (difficulty < 1e12) {
    scale = 1000000ULL;
    denom = u128_from_double(round(difficulty * 1000000.0));
  } else if (difficulty < 3.4e38) {
    scale = 1ULL;
    denom = u128_from_double(round(difficulty));
  } else {
    memset(out_target_be, 0x00, 32);
    return true;
  }

  if (denom.hi == 0 && denom.lo <= scale) {
    memset(out_target_be, 0xff, 32);
    return true;
  }

  uint32_t num[9];
  uint64_t carry = 0;
  for (int i = 8; i >= 1; i--) {
    uint64_t prod = ((uint64_t)UINT32_MAX) * scale + carry;
    num[i] = (uint32_t)(prod & 0xffffffffULL);
    carry = prod >> 32;
  }
  num[0] = (uint32_t)carry;

  uint32_t quot[9];
  u128_t rem = {0, 0};
  for (int limb_idx = 0; limb_idx < 9; limb_idx++) {
    uint32_t limb = num[limb_idx];
    uint32_t q_limb = 0;
    for (int bit = 31; bit >= 0; bit--) {
      uint64_t carry_bit = rem.hi >> 63;
      rem.hi = (rem.hi << 1) | (rem.lo >> 63);
      rem.lo = (rem.lo << 1) | (uint64_t)((limb >> bit) & 1u);
      if (carry_bit != 0 || u128_ge(rem, denom)) {
        rem = u128_sub(rem, denom);
        q_limb |= (1u << bit);
      }
    }
    quot[limb_idx] = q_limb;
  }

  if (quot[0] > 0) {
    memset(out_target_be, 0xff, 32);
    return true;
  }

  for (int i = 0; i < 8; i++) {
    store_be32(out_target_be + i * 4, quot[i + 1]);
  }
  return true;
}

static uint32_t verify_cycle_with_keys(
    const siphash_keys_t *keys,
    const uint32_t *edges,
    uint32_t edge_bits,
    size_t proof_size) {
  if (!validate_params(edge_bits, proof_size, CZ_MAX_VERIFY_EDGE_BITS) || edges == NULL) {
    return CZ_POW_INVALID_PARAMS;
  }

  uint64_t nedges = 1ULL << edge_bits;
  uint32_t edgemask = (uint32_t)(nedges - 1ULL);
  uint32_t nodemask = (uint32_t)((2ULL * nedges) - 1ULL);

  uint64_t sips[EDGE_BLOCK_SIZE];
  uint32_t cached_base = UINT32_MAX;
  uint32_t uv[2 * CZ_MAX_PROOF_SIZE];
  uint32_t xoruv = 0;

  for (size_t n = 0; n < proof_size; n++) {
    uint32_t e = edges[n];
    if (e > edgemask) {
      return CZ_POW_TOO_BIG;
    }
    if (n > 0 && e <= edges[n - 1]) {
      return CZ_POW_TOO_SMALL;
    }
    uint32_t base = e & ~EDGE_BLOCK_MASK;
    if (base != cached_base) {
      sipblock_fill(keys, base, sips);
      cached_base = base;
    }
    uint64_t edge_val = sips[e & EDGE_BLOCK_MASK];
    uint32_t u = ((uint32_t)edge_val) & nodemask;
    uint32_t v = ((uint32_t)(edge_val >> 32)) & nodemask;
    uv[2 * n] = u;
    uv[2 * n + 1] = v;
    xoruv ^= u ^ v;
  }

  if (xoruv != 0) {
    return CZ_POW_NON_MATCHING;
  }

  size_t double_len = 2 * proof_size;
  size_t n = 0;
  size_t i = 0;
  do {
    size_t j = i;
    for (size_t k = (i + 1) % double_len; k != i; k = (k + 1) % double_len) {
      if (uv[k] == uv[i]) {
        if (j != i) {
          return CZ_POW_BRANCH;
        }
        j = k;
      }
    }
    if (j == i) {
      return CZ_POW_DEAD_END;
    }
    i = j ^ 1u;
    n++;
  } while (i != 0);

  return (n == proof_size) ? CZ_POW_OK : CZ_POW_SHORT_CYCLE;
}

static bool compute_cycle_hash(
    const uint32_t *edges,
    size_t proof_size,
    uint32_t edge_bits,
    uint8_t out_rev[32],
    uint8_t out_be[32]) {
  if (!validate_params(edge_bits, proof_size, CZ_MAX_VERIFY_EDGE_BITS) || edges == NULL) {
    return false;
  }

  size_t total_bytes = (proof_size * (size_t)edge_bits + 7u) / 8u;
  uint8_t hashdata[(CZ_MAX_PROOF_SIZE * CZ_MAX_VERIFY_EDGE_BITS + 7u) / 8u];
  memset(hashdata, 0, total_bytes);

  size_t bytepos = 0;
  uint32_t bitpos = 0;
  for (size_t i = 0; i < proof_size; i++) {
    uint32_t node = edges[i];
    for (uint32_t j = 0; j < edge_bits; j++) {
      if ((node >> j) & 1u) {
        hashdata[bytepos] |= (uint8_t)(1u << bitpos);
      }
      bitpos++;
      if (bitpos == 8u) {
        bitpos = 0;
        bytepos++;
      }
    }
  }

  uint8_t digest[32];
  blake2b(digest, sizeof(digest), hashdata, total_bytes, NULL, 0);
  if (out_be != NULL) {
    memcpy(out_be, digest, 32);
  }
  if (out_rev != NULL) {
    for (size_t i = 0; i < 32; i++) {
      out_rev[i] = digest[31 - i];
    }
  }
  return true;
}

uint32_t cz_verify_cycle(
    const uint8_t *header,
    size_t header_len,
    const uint32_t *edges,
    uint32_t edge_bits,
    size_t proof_size) {
  if ((header_len > 0 && header == NULL) || edges == NULL) {
    return CZ_POW_INVALID_PARAMS;
  }
  if (!validate_params(edge_bits, proof_size, CZ_MAX_VERIFY_EDGE_BITS)) {
    return CZ_POW_INVALID_PARAMS;
  }
  siphash_keys_t keys;
  set_header_keys(header, header_len, &keys);
  return verify_cycle_with_keys(&keys, edges, edge_bits, proof_size);
}

uint32_t cz_cycle_hash(
    const uint32_t *edges,
    size_t proof_size,
    uint32_t edge_bits,
    uint8_t *out_rev_hash) {
  if (edges == NULL || out_rev_hash == NULL) {
    return CZ_POW_INVALID_PARAMS;
  }
  if (!compute_cycle_hash(edges, proof_size, edge_bits, out_rev_hash, NULL)) {
    return CZ_POW_INVALID_PARAMS;
  }
  return CZ_POW_OK;
}

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
    uint8_t *out_rev_hash) {
  if ((challenge_len > 0 && challenge == NULL) || edges == NULL) {
    return CZ_POW_INVALID_PARAMS;
  }
  if (!validate_params(edge_bits, proof_size, CZ_MAX_VERIFY_EDGE_BITS)) {
    return CZ_POW_INVALID_PARAMS;
  }

  uint8_t target_be[32];
  if (!target_from_difficulty(difficulty, target_be)) {
    return CZ_POW_INVALID_PARAMS;
  }

  uint64_t nonce = ((uint64_t)nonce_lo) | (((uint64_t)nonce_hi) << 32);
  siphash_keys_t keys;
  set_challenge_nonce_keys(challenge, challenge_len, nonce, &keys);

  uint32_t rc = verify_cycle_with_keys(&keys, edges, edge_bits, proof_size);
  if (rc != CZ_POW_OK) {
    return rc;
  }

  uint8_t rev[32];
  uint8_t be[32];
  if (!compute_cycle_hash(edges, proof_size, edge_bits, rev, be)) {
    return CZ_POW_INVALID_PARAMS;
  }

  if (out_rev_hash != NULL) {
    memcpy(out_rev_hash, rev, 32);
  }

  if (has_expected_hash != 0) {
    if (expected_rev_hash == NULL) {
      return CZ_POW_INVALID_PARAMS;
    }
    if (memcmp(expected_rev_hash, rev, 32) != 0) {
      return CZ_POW_HASH_MISMATCH;
    }
  }

  if (memcmp(be, target_be, 32) > 0) {
    return CZ_POW_DIFFICULTY_TOO_LOW;
  }

  return CZ_POW_OK;
}

typedef struct {
  uint32_t next;
  uint32_t to;
  uint32_t edge;
} cz_link_t;

struct cz_solver {
  uint32_t edge_bits;
  size_t n_edges;
  size_t n_nodes;
  size_t deg_bytes;
  uint64_t *edges_uv;
  uint32_t *active;
  uint8_t *deg;
  uint32_t *adj;
  uint32_t *touched;
  size_t touched_cap;
  cz_link_t *links;
  size_t links_cap;
  uint32_t *visited;
};

static inline void inc_deg(uint8_t *deg, uint32_t node) {
  size_t idx = (size_t)(node >> 2);
  uint32_t shift = (node & 3u) << 1;
  uint8_t byte = deg[idx];
  if (((byte >> shift) & 3u) < 2u) {
    deg[idx] = (uint8_t)(byte + (1u << shift));
  }
}

static inline bool is_deg_ge2(const uint8_t *deg, uint32_t node) {
  size_t idx = (size_t)(node >> 2);
  uint32_t shift = (node & 3u) << 1;
  return ((deg[idx] >> shift) & 3u) >= 2u;
}

static inline bool is_visited(const cz_solver_t *s, uint32_t node) {
  return (s->visited[node >> 5] & (1u << (node & 31u))) != 0;
}

static inline void set_visited(cz_solver_t *s, uint32_t node) {
  s->visited[node >> 5] |= (1u << (node & 31u));
}

static inline void clear_visited(cz_solver_t *s, uint32_t node) {
  s->visited[node >> 5] &= ~(1u << (node & 31u));
}

static int cmp_u32(const void *a, const void *b) {
  uint32_t va = *(const uint32_t *)a;
  uint32_t vb = *(const uint32_t *)b;
  return (va > vb) - (va < vb);
}

static bool ensure_links_capacity(cz_solver_t *s, size_t needed) {
  if (needed <= s->links_cap) {
    return true;
  }
  size_t new_cap = s->links_cap ? s->links_cap * 2u : 2048u;
  while (new_cap < needed) {
    new_cap *= 2u;
  }
  cz_link_t *grown = (cz_link_t *)realloc(s->links, new_cap * sizeof(cz_link_t));
  if (!grown) {
    return false;
  }
  s->links = grown;
  s->links_cap = new_cap;
  return true;
}

static bool ensure_touched_capacity(cz_solver_t *s, size_t needed) {
  if (needed <= s->touched_cap) {
    return true;
  }
  size_t new_cap = s->touched_cap ? s->touched_cap * 2u : 4096u;
  while (new_cap < needed) {
    new_cap *= 2u;
  }
  uint32_t *grown = (uint32_t *)realloc(s->touched, new_cap * sizeof(uint32_t));
  if (!grown) {
    return false;
  }
  s->touched = grown;
  s->touched_cap = new_cap;
  return true;
}

cz_solver_t *cz_solver_new(uint32_t edge_bits) {
  if (edge_bits < CZ_MIN_EDGE_BITS || edge_bits > CZ_MAX_MINE_EDGE_BITS) {
    return NULL;
  }
  cz_solver_t *s = (cz_solver_t *)calloc(1, sizeof(cz_solver_t));
  if (!s) {
    return NULL;
  }

  s->edge_bits = edge_bits;
  s->n_edges = (size_t)1u << edge_bits;
  s->n_nodes = 2u * s->n_edges;
  s->deg_bytes = (s->n_nodes + 3u) / 4u;
  size_t vis_words = (s->n_nodes + 31u) / 32u;

  s->edges_uv = (uint64_t *)malloc(s->n_edges * sizeof(uint64_t));
  s->active = (uint32_t *)malloc(s->n_edges * sizeof(uint32_t));
  s->deg = (uint8_t *)malloc(s->deg_bytes);
  s->adj = (uint32_t *)malloc(s->n_nodes * sizeof(uint32_t));
  s->touched_cap = 4096u;
  s->touched = (uint32_t *)malloc(s->touched_cap * sizeof(uint32_t));
  s->links_cap = 2048u;
  s->links = (cz_link_t *)malloc(s->links_cap * sizeof(cz_link_t));
  s->visited = (uint32_t *)calloc(vis_words, sizeof(uint32_t));

  if (!s->edges_uv || !s->active || !s->deg || !s->adj || !s->touched || !s->links || !s->visited) {
    cz_solver_free(s);
    return NULL;
  }

  memset(s->adj, 0xff, s->n_nodes * sizeof(uint32_t));
  return s;
}

uint32_t cz_solver_memory_bytes(uint32_t edge_bits) {
  if (edge_bits < CZ_MIN_EDGE_BITS || edge_bits > CZ_MAX_MINE_EDGE_BITS) {
    return 0;
  }
  size_t n_edges = (size_t)1u << edge_bits;
  size_t n_nodes = 2u * n_edges;
  size_t deg_bytes = (n_nodes + 3u) / 4u;
  size_t vis_words = (n_nodes + 31u) / 32u;
  size_t total =
      sizeof(cz_solver_t) +
      n_edges * sizeof(uint64_t) +
      n_edges * sizeof(uint32_t) +
      deg_bytes +
      n_nodes * sizeof(uint32_t) +
      4096u * sizeof(uint32_t) +
      2048u * sizeof(cz_link_t) +
      vis_words * sizeof(uint32_t);
  return (uint32_t)total;
}

void cz_solver_free(cz_solver_t *s) {
  if (!s) {
    return;
  }
  free(s->edges_uv);
  free(s->active);
  free(s->deg);
  free(s->adj);
  free(s->touched);
  free(s->links);
  free(s->visited);
  free(s);
}

static bool dfs_cycle(
    cz_solver_t *s,
    size_t len,
    uint32_t curr,
    uint32_t dest,
    size_t proof_size,
    const uint8_t target_be[32],
    uint32_t path[CZ_MAX_PROOF_SIZE],
    uint32_t *cycles_found,
    uint32_t *out_edges,
    uint8_t out_rev_hash[32]) {
  if (len == proof_size) {
    if (curr == dest) {
      uint32_t sorted[CZ_MAX_PROOF_SIZE];
      memcpy(sorted, path, proof_size * sizeof(uint32_t));
      qsort(sorted, proof_size, sizeof(uint32_t), cmp_u32);

      uint8_t rev[32] = {0};
      uint8_t be[32] = {0};
      if (!compute_cycle_hash(sorted, proof_size, s->edge_bits, rev, be)) {
        return false;
      }
      if (cycles_found != NULL) {
        (*cycles_found)++;
      }
      if (memcmp(be, target_be, 32) <= 0) {
        memcpy(out_edges, sorted, proof_size * sizeof(uint32_t));
        memcpy(out_rev_hash, rev, 32);
        return true;
      }
    }
    return false;
  }

  if (curr == dest || is_visited(s, curr)) {
    return false;
  }

  uint32_t link_idx = s->adj[curr];
  if (link_idx == CZ_NIL) {
    return false;
  }

  set_visited(s, curr);
  while (link_idx != CZ_NIL) {
    cz_link_t link = s->links[link_idx];
    path[len] = link.edge;
    if (dfs_cycle(s, len + 1u, link.to, dest, proof_size, target_be, path, cycles_found, out_edges, out_rev_hash)) {
      clear_visited(s, curr);
      return true;
    }
    link_idx = link.next;
  }
  clear_visited(s, curr);
  return false;
}

static bool solve_nonce(
    cz_solver_t *s,
    const siphash_keys_t *keys,
    size_t proof_size,
    const uint8_t target_be[32],
    uint32_t *cycles_found,
    uint32_t *out_edges,
    uint8_t out_rev_hash[32]) {
  size_t n_edges = s->n_edges;
  uint32_t nodemask = (uint32_t)(s->n_nodes - 1u);

  memset(s->deg, 0, s->deg_bytes);
  uint64_t sips[EDGE_BLOCK_SIZE];
  for (size_t block = 0; block < n_edges; block += EDGE_BLOCK_SIZE) {
    sipblock_fill(keys, (uint32_t)block, sips);
    for (size_t i = 0; i < EDGE_BLOCK_SIZE; i++) {
      size_t e = block + i;
      uint64_t edge_val = sips[i];
      uint32_t u = ((uint32_t)edge_val) & nodemask;
      uint32_t v = ((uint32_t)(edge_val >> 32)) & nodemask;
      s->edges_uv[e] = ((uint64_t)u) | (((uint64_t)v) << 32);
      if (u != v) {
        inc_deg(s->deg, u);
        inc_deg(s->deg, v);
      }
    }
  }

  size_t active_len = 0;
  for (size_t e = 0; e < n_edges; e++) {
    uint64_t uv = s->edges_uv[e];
    uint32_t u = (uint32_t)uv;
    uint32_t v = (uint32_t)(uv >> 32);
    if (u != v && is_deg_ge2(s->deg, u) && is_deg_ge2(s->deg, v)) {
      s->active[active_len++] = (uint32_t)e;
    }
  }

  for (int round = 0; round < 32; round++) {
    if (active_len < proof_size) {
      return false;
    }
    memset(s->deg, 0, s->deg_bytes);
    for (size_t i = 0; i < active_len; i++) {
      uint64_t uv = s->edges_uv[s->active[i]];
      inc_deg(s->deg, (uint32_t)uv);
      inc_deg(s->deg, (uint32_t)(uv >> 32));
    }
    size_t write_idx = 0;
    for (size_t i = 0; i < active_len; i++) {
      uint32_t e = s->active[i];
      uint64_t uv = s->edges_uv[e];
      if (is_deg_ge2(s->deg, (uint32_t)uv) && is_deg_ge2(s->deg, (uint32_t)(uv >> 32))) {
        s->active[write_idx++] = e;
      }
    }
    if (write_idx == active_len) {
      break;
    }
    active_len = write_idx;
  }

  if (active_len < proof_size) {
    return false;
  }

  if (!ensure_links_capacity(s, active_len * 2u) ||
      !ensure_touched_capacity(s, active_len * 2u)) {
    return false;
  }

  size_t n_links = 0;
  size_t n_touched = 0;
  uint32_t path[CZ_MAX_PROOF_SIZE];
  bool found = false;

  for (size_t idx = 0; idx < active_len; idx++) {
    uint32_t e = s->active[idx];
    uint64_t uv = s->edges_uv[e];
    uint32_t u = (uint32_t)uv;
    uint32_t v = (uint32_t)(uv >> 32);

    // Drop parallel duplicate edge to match cuckarooz/graph.hpp
    bool is_dupe = false;
    for (uint32_t check = s->adj[u]; check != CZ_NIL; check = s->links[check].next) {
      if (s->links[check].to == v) {
        is_dupe = true;
        break;
      }
    }
    if (is_dupe) {
      continue;
    }

    if (s->adj[u] != CZ_NIL && s->adj[v] != CZ_NIL) {
      path[0] = e;
      if (dfs_cycle(s, 1u, v, u, proof_size, target_be, path, cycles_found, out_edges, out_rev_hash)) {
        found = true;
        break;
      }
    }

    if (s->adj[u] == CZ_NIL) {
      s->touched[n_touched++] = u;
    }
    if (s->adj[v] == CZ_NIL) {
      s->touched[n_touched++] = v;
    }

    uint32_t u_link = (uint32_t)n_links++;
    s->links[u_link] = (cz_link_t){s->adj[u], v, e};
    s->adj[u] = u_link;

    uint32_t v_link = (uint32_t)n_links++;
    s->links[v_link] = (cz_link_t){s->adj[v], u, e};
    s->adj[v] = v_link;
  }

  for (size_t i = 0; i < n_touched; i++) {
    s->adj[s->touched[i]] = CZ_NIL;
  }

  return found;
}

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
    uint32_t *out_cycles_found) {
  if (solver == NULL ||
      (challenge_len > 0 && challenge == NULL) ||
      out_nonce_lo == NULL ||
      out_nonce_hi == NULL ||
      out_edges == NULL ||
      out_rev_hash == NULL) {
    return CZ_POW_INVALID_PARAMS;
  }

  if (!validate_params(solver->edge_bits, proof_size, CZ_MAX_MINE_EDGE_BITS) || num_nonces == 0) {
    return CZ_POW_INVALID_PARAMS;
  }

  uint8_t target_be[32];
  if (!target_from_difficulty(difficulty, target_be)) {
    return CZ_POW_INVALID_PARAMS;
  }

  uint64_t start_nonce = ((uint64_t)start_nonce_lo) | (((uint64_t)start_nonce_hi) << 32);
  uint32_t checked = 0;
  uint32_t cycles_found = 0;

  for (uint32_t offset = 0; offset < num_nonces; offset++) {
    uint64_t nonce = start_nonce + (uint64_t)offset;
    siphash_keys_t keys;
    set_challenge_nonce_keys(challenge, challenge_len, nonce, &keys);
    checked++;

    if (solve_nonce(solver, &keys, proof_size, target_be, &cycles_found, out_edges, out_rev_hash)) {
      *out_nonce_lo = (uint32_t)nonce;
      *out_nonce_hi = (uint32_t)(nonce >> 32);
      if (out_nonces_checked != NULL) {
        *out_nonces_checked = checked;
      }
      if (out_cycles_found != NULL) {
        *out_cycles_found = cycles_found;
      }
      return 1;
    }
  }

  if (out_nonces_checked != NULL) {
    *out_nonces_checked = checked;
  }
  if (out_cycles_found != NULL) {
    *out_cycles_found = cycles_found;
  }
  return 0;
}
