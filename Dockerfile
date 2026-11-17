FROM emscripten/emsdk AS build-stage

COPY src /src

RUN mkdir -p /src/build && emcc /src/cuckarooz.c /src/crypto/blake2b-ref.c \
  -I/src -I/src/crypto -std=c11 -O3 -lm --no-entry \
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sALLOW_MEMORY_GROWTH=1 \
  -sEXPORTED_FUNCTIONS='["_malloc","_free","_cz_verify_cycle","_cz_cycle_hash","_cz_verify_challenge","_cz_solver_new","_cz_solver_free","_cz_solver_memory_bytes","_cz_solver_mine_batch"]' \
  -sEXPORTED_RUNTIME_METHODS='["HEAPU8","HEAPU32"]' \
  -sEXPORT_NAME=createCuckooModule \
  -o /src/build/cuckarooz.js

# Output stage
FROM scratch
COPY --from=build-stage /src/build/cuckarooz.js /
COPY --from=build-stage /src/build/cuckarooz.wasm /
