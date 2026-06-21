/*
 * at1_decode.h -- public C ABI for the AT-1 reference decoder.
 *
 * Decode an AT-1 container into the original bytes. The decoder is bounds-checked
 * against malformed/hostile input and NEVER calls exit() or aborts the host
 * process when used through this API -- it returns an error code instead. Safe to
 * embed in servers, language runtimes (via FFI), and WebAssembly.
 *
 *   Build (library):   cc -O2 -DAT1_NO_MAIN -c at1_decode.c -o at1_decode.o
 *   Build (CLI):       cc -O2 -o at1_decode at1_decode.c -llzma -lzstd
 *   Link:              -llzma -lzstd  (or an embedded decode-only profile)
 */
#ifndef AT1_DECODE_H
#define AT1_DECODE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes */
#define AT1_OK          0   /* success: *out / *out_len set, free with at1_free */
#define AT1_ERR_CORRUPT 2   /* malformed or hostile input was rejected           */
#define AT1_ERR_BACKEND 3   /* resource / backend (xz, zstd, allocation) error   */

/*
 * Decode the AT-1 container in [in, in+in_len) to a freshly-allocated buffer.
 * On AT1_OK, *out points to malloc'd output of *out_len bytes (free via at1_free).
 * On error, *out is not modified and nothing must be freed. Never aborts.
 */
int at1_decode_buffer(const uint8_t *in, size_t in_len,
                      uint8_t **out, size_t *out_len);

/* Free a buffer returned by at1_decode_buffer. */
void at1_free(uint8_t *p);

/* Human-readable version string. */
const char *at1_version(void);

#ifdef __cplusplus
}
#endif

#endif /* AT1_DECODE_H */
