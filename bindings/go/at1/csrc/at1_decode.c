/*
 * at1_decode.c -- reference AT-1 reconstructor (decoder).
 *
 * Implements the AT-1 container + RAW fallback + streaming + the columnar
 * codec (the tabular/telemetry production path) per AT1_FORMAT_SPEC.md.
 *
 * The decoder is intentionally tiny and dependency-light: varint/zigzag,
 * delta/column reassembly, RFC-4180 re-quoting, and one xz block decode via
 * liblzma. No JSON/CSV libraries, no floating point. Target: a small, portable
 * binary that runs on servers, phones, and embedded targets.
 *
 *   Build:  cc -O2 -o at1_decode at1_decode.c -llzma
 *   Use:    ./at1_decode input.at1 output
 *
 * NOTE: This is reference source. Verify against testvectors/ via `make test`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#ifndef AT1_NO_XZ
#include <lzma.h>      /* xz/LZMA backend; define AT1_NO_XZ to build without liblzma
                          (e.g. the WASM target, where only zstd/stored are wired) */
#endif
#include <zstd.h>
#ifdef _OPENMP
#include <omp.h>   /* opt-in: -fopenmp enables multithreaded queryable-block decode */
#endif

#define B_XZ 0
#define B_ZSTD 1
#define B_STORED 2   /* no compression: payload is already-compressed blocks */

#ifdef AT1_PROFILE
/* opt-in decode profiling (never in production builds): split wall-clock between
 * the backend library decompress (xz/zstd, not ours) and our own transforms. */
#include <time.h>
static double g_prof_backend_secs = 0.0;
static size_t g_prof_backend_out = 0;
static double g_prof_refresh_secs = 0.0;   /* qcol/qjson row-group refresh (backend + split_nl) */
#endif

/* ---------- library-safe failure path ----------
 * As a CLI the decoder exits on error. As a library (at1_decode_buffer) it must
 * never call exit(): instead it longjmps back to the entry point and returns an
 * error code, so the host process survives malformed input. */
static jmp_buf g_at1_errjmp;
static int g_at1_in_lib = 0;
static int g_at1_err = 0;
static void at1_fail(int code) {
    if (g_at1_in_lib) { g_at1_err = code; longjmp(g_at1_errjmp, 1); }
    exit(code);
}

/* ---------- dynamic byte buffer ---------- */
typedef struct { unsigned char *p; size_t n, cap; } Buf;
static void buf_reserve(Buf *b, size_t extra) {
    if (b->n + extra <= b->cap) return;
    size_t c = b->cap ? b->cap : 64;
    while (c < b->n + extra) c <<= 1;
    b->p = realloc(b->p, c); if (!b->p) { fprintf(stderr, "OOM\n"); at1_fail(3); }
    b->cap = c;
}
static void buf_put(Buf *b, const void *src, size_t n) {
    buf_reserve(b, n); memcpy(b->p + b->n, src, n); b->n += n;
}
static void buf_putc(Buf *b, unsigned char c) { buf_reserve(b, 1); b->p[b->n++] = c; }

/* ---------- SHA-256 (compact, public-domain style) ----------
 * Used only to verify the optional integrity trailer (sha256(original) + magic):
 * we hash the reconstructed output and compare, so the native decoder confirms
 * decode == original exactly like the Python reference. */
typedef struct { uint32_t s[8]; uint64_t len; unsigned char buf[64]; size_t n; } Sha256;
static uint32_t sha_ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static void sha256_init(Sha256 *c) {
    static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(c->s, iv, sizeof iv); c->len = 0; c->n = 0;
}
static void sha256_block(Sha256 *c, const unsigned char *p) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
    uint32_t w[64], a, b, e, f, g, h, d, cc, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 | (uint32_t)p[i*4+2] << 8 | p[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = sha_ror(w[i-15],7) ^ sha_ror(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = sha_ror(w[i-2],17) ^ sha_ror(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = sha_ror(e,6) ^ sha_ror(e,11) ^ sha_ror(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = sha_ror(a,2) ^ sha_ror(a,13) ^ sha_ror(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void sha256_update(Sha256 *c, const unsigned char *p, size_t n) {
    c->len += n;
    while (n) {
        size_t take = 64 - c->n; if (take > n) take = n;
        memcpy(c->buf + c->n, p, take); c->n += take; p += take; n -= take;
        if (c->n == 64) { sha256_block(c, c->buf); c->n = 0; }
    }
}
static void sha256_final(Sha256 *c, unsigned char out[32]) {
    uint64_t bits = c->len * 8;
    unsigned char pad = 0x80;
    sha256_update(c, &pad, 1);
    unsigned char z = 0;
    while (c->n != 56) sha256_update(c, &z, 1);
    unsigned char ln[8]; int i;
    for (i = 0; i < 8; i++) ln[i] = (unsigned char)(bits >> (56 - i*8));
    sha256_update(c, ln, 8);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(c->s[i] >> 24); out[i*4+1] = (unsigned char)(c->s[i] >> 16);
        out[i*4+2] = (unsigned char)(c->s[i] >> 8);  out[i*4+3] = (unsigned char)(c->s[i]);
    }
}

/* ---------- slices & values ---------- */
typedef struct { const unsigned char *p; size_t n; } Str; /* may point into a buffer or owned */

/* ---------- varints over a cursor ---------- */
typedef struct { const unsigned char *p; size_t pos, len; } Cur;
static uint64_t rd_uv(Cur *c) {
    uint64_t r = 0; int s = 0; unsigned char b;
    do { if (c->pos >= c->len) { fprintf(stderr, "varint overrun\n"); at1_fail(3); }
         b = c->p[c->pos++]; r |= (uint64_t)(b & 0x7F) << s; s += 7; } while (b & 0x80);
    return r;
}
static int64_t rd_sv(Cur *c) { uint64_t z = rd_uv(c); return (int64_t)(z >> 1) ^ -(int64_t)(z & 1); }
/* reject malformed/hostile input cleanly (never crash) */
#define DIE(msg) do { fprintf(stderr, "corrupt input: %s\n", msg); at1_fail(2); } while (0)
/* bounds-checked slice of n bytes from a cursor; returns ptr, advances pos */
static const unsigned char *rd_bytes(Cur *c, uint64_t n) {
    if (n > c->len || c->pos + n > c->len) DIE("stream slice OOB");
    const unsigned char *p = c->p + c->pos; c->pos += n; return p;
}

/* Output ceiling: a tiny crafted .xz/.zstd can claim/expand to enormous size
   (decompression bomb). Cap the output so untrusted input can't exhaust memory.
   Override at build time with -DAT1_MAX_DECODE=<bytes>. Needed by zstd_decode
   too, so it lives OUTSIDE the AT1_NO_XZ guard. On 32-bit targets (wasm32!) the
   16 GiB constant would overflow size_t to 0 and reject EVERY decode, so the
   default there is 1 GiB. */
#ifndef AT1_MAX_DECODE
#if SIZE_MAX > 0xffffffffULL
#define AT1_MAX_DECODE ((size_t)16 * 1024 * 1024 * 1024)   /* 16 GiB (64-bit) */
#else
#define AT1_MAX_DECODE ((size_t)1 << 30)                   /* 1 GiB (32-bit) */
#endif
#endif

/* ---------- xz one-shot decode (arbitrary size) ---------- */
#ifndef AT1_NO_XZ
static unsigned char *xz_decode(const unsigned char *in, size_t in_len, size_t *out_len) {
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&s, UINT64_MAX, 0) != LZMA_OK) { fprintf(stderr, "lzma init\n"); at1_fail(3); }
    if (in_len > (SIZE_MAX - 4096) / 4) { fprintf(stderr, "xz size\n"); at1_fail(3); }
    size_t cap = in_len * 4 + 4096; unsigned char *out = malloc(cap);
    if (!out) { fprintf(stderr, "xz alloc\n"); at1_fail(3); }
    s.next_in = in; s.avail_in = in_len; s.next_out = out; s.avail_out = cap;
    for (;;) {
        lzma_ret r = lzma_code(&s, LZMA_FINISH);
        if (r == LZMA_STREAM_END) break;
        if (r != LZMA_OK) { fprintf(stderr, "lzma decode err %d\n", r); at1_fail(3); }
        if (s.avail_out == 0) {
            if (cap >= AT1_MAX_DECODE) { fprintf(stderr, "xz output too large\n"); at1_fail(3); }
            size_t used = cap;
            cap = (cap > AT1_MAX_DECODE / 2) ? AT1_MAX_DECODE : cap << 1;
            unsigned char *n = realloc(out, cap);
            if (!n) { fprintf(stderr, "xz realloc\n"); free(out); at1_fail(3); }
            out = n; s.next_out = out + used; s.avail_out = cap - used;
        }
    }
    *out_len = cap - s.avail_out; lzma_end(&s); return out;
}
#endif /* AT1_NO_XZ */

/* ---------- zstd decode ---------- */
static unsigned char *zstd_decode(const unsigned char *in, size_t in_len, size_t *out_len) {
    unsigned long long sz = ZSTD_getFrameContentSize(in, in_len);
    if (sz == ZSTD_CONTENTSIZE_ERROR || sz == ZSTD_CONTENTSIZE_UNKNOWN) { fprintf(stderr, "zstd size\n"); at1_fail(3); }
    if (sz > AT1_MAX_DECODE) { fprintf(stderr, "zstd output too large\n"); at1_fail(3); }
    unsigned char *out = malloc(sz ? sz : 1);
    if (!out) { fprintf(stderr, "zstd alloc %llu\n", sz); at1_fail(3); }
    size_t r = ZSTD_decompress(out, sz, in, in_len);
    if (ZSTD_isError(r)) { fprintf(stderr, "zstd decode: %s\n", ZSTD_getErrorName(r)); at1_fail(3); }
    *out_len = r; return out;
}

/* dispatch on backend id (0=xz, 1=zstd, 2=stored) */
static unsigned char *backend_decode(int backend, const unsigned char *in, size_t in_len, size_t *out_len) {
#ifdef AT1_PROFILE
    clock_t _t0 = clock();
    unsigned char *_r;
    if (backend == B_ZSTD) _r = zstd_decode(in, in_len, out_len);
    else if (backend == B_STORED) {
        _r = malloc(in_len ? in_len : 1);
        if (!_r) { fprintf(stderr, "stored alloc\n"); at1_fail(3); }
        memcpy(_r, in, in_len); *out_len = in_len;
    }
#ifdef AT1_NO_XZ
    else { fprintf(stderr, "xz backend not supported (AT1_NO_XZ)\n"); at1_fail(3); _r = NULL; }
#else
    else _r = xz_decode(in, in_len, out_len);
#endif
    g_prof_backend_secs += (double)(clock() - _t0) / CLOCKS_PER_SEC;
    g_prof_backend_out += *out_len;
    return _r;
#else
    if (backend == B_ZSTD) return zstd_decode(in, in_len, out_len);
    if (backend == B_STORED) {
        unsigned char *o = malloc(in_len ? in_len : 1);
        if (!o) { fprintf(stderr, "stored alloc\n"); at1_fail(3); }
        memcpy(o, in, in_len); *out_len = in_len; return o;
    }
#ifdef AT1_NO_XZ
    fprintf(stderr, "xz backend not supported in this build (AT1_NO_XZ)\n"); at1_fail(3);
    return NULL;  /* unreachable */
#else
    return xz_decode(in, in_len, out_len);
#endif
#endif
}

/* ---------- packed stream set: name -> (data,len) ---------- */
typedef struct { char name[32]; unsigned char *data; size_t len; } Stream;
/* 256: qjson2 (codec 11) namespaces up to 32 templates x ~6 sub-streams in one
 * container, and bundles (codec 12) carry one stream per entry. Was 32. */
typedef struct { Stream s[256]; int n; } Streams;

/* returns 1 on success, 0 on malformed framing (caller must reject) */
static int unpack(const unsigned char *body, size_t body_len, Streams *out) {
    Cur c = { body, 0, body_len }; out->n = 0;
    uint64_t ns = rd_uv(&c);
    if (ns > (uint64_t)(sizeof(out->s) / sizeof(out->s[0]))) return 0;  /* fixed array bound */
    for (uint64_t i = 0; i < ns; i++) {
        uint64_t nl = rd_uv(&c);
        if (nl > body_len || c.pos + nl > body_len) return 0;          /* name OOB */
        Stream *st = &out->s[out->n];
        size_t k = nl < sizeof(st->name) - 1 ? nl : sizeof(st->name) - 1;
        memcpy(st->name, c.p + c.pos, k); st->name[k] = 0; c.pos += nl;
        if (c.pos >= body_len) return 0;                                /* backend byte OOB */
        int backend = c.p[c.pos++];
        uint64_t cl = rd_uv(&c);
        if (cl > body_len || c.pos + cl > body_len) return 0;           /* comp data OOB */
        st->data = backend_decode(backend, c.p + c.pos, cl, &st->len); c.pos += cl;
        out->n++;
    }
    return 1;
}
/* never returns NULL: an absent stream reads as empty (len 0) so codecs can't
   NULL-deref on malformed input. */
static unsigned char EMPTY_BYTE[1] = { 0 };
static Stream EMPTY_STREAM = { "", EMPTY_BYTE, 0 };
static Stream *get(Streams *s, const char *name) {
    for (int i = 0; i < s->n; i++) if (!strcmp(s->s[i].name, name)) return &s->s[i];
    return &EMPTY_STREAM;
}

/* ---------- decimal helpers (no floating point) ---------- */
/* Fast unsigned->decimal ASCII (no snprintf): writes the digits of `a` into `buf`
 * (needs >= 20 bytes), returns the digit count, no NUL terminator. Byte-identical
 * to snprintf("%llu", a) for every value (0 -> "0"). snprintf re-parses a format
 * string + consults locale on every call; this is ~5-10x faster and is the per-row
 * hot path for integer/decimal columns. Pure and trivially verifiable. */
static int u64toa(unsigned long long a, char *buf) {
    char tmp[20]; int i = 0;
    do { tmp[i++] = (char)('0' + (int)(a % 10u)); a /= 10u; } while (a);
    for (int j = 0; j < i; j++) buf[j] = tmp[i - 1 - j];
    return i;
}
/* Pure formatters: write decimal text into `o` (no allocation) and return the byte
 * length. `o` needs >= 24 bytes for fmt_int, >= 48 for fmt_fixed. These are the single
 * source of truth so the malloc-backed (own_*) and arena-backed (arena_*) emitters are
 * byte-identical. */
static int fmt_int(char *o, long long v) {
    int n = 0; int neg = v < 0;
    unsigned long long a = neg ? -(unsigned long long)v : (unsigned long long)v;
    if (neg) o[n++] = '-';
    n += u64toa(a, o + n);
    return n;
}
static int fmt_fixed(char *o, long long v, int D) {  /* caller validates 0 <= D <= 18 */
    char digits[24]; int neg = v < 0; unsigned long long a = neg ? -(unsigned long long)v : v;
    int dn = u64toa(a, digits);
    char pad[40]; int pn = dn; const char *src = digits;
    if (dn <= D) { pn = D + 1; memset(pad, '0', pn - dn); memcpy(pad + (pn - dn), digits, dn); src = pad; }
    int n = 0; if (neg) o[n++] = '-';
    int intlen = pn - D; memcpy(o + n, src, intlen); n += intlen; o[n++] = '.';
    memcpy(o + n, src + intlen, D); n += D;
    return n;
}
static Str own_int(long long v) {
    char tmp[24]; int n = fmt_int(tmp, v);
    char *p = malloc(n ? n : 1); if (!p) { fprintf(stderr, "OOM\n"); at1_fail(3); }
    memcpy(p, tmp, n); Str s = { (unsigned char *)p, (size_t)n }; return s;
}
static Str own_fixed(long long v, int D) {
    /* D is the decimal scale (attacker-controlled byte). A long long has at most 19
       significant digits, so D>18 is nonsensical and would overflow the buffers below. */
    if (D < 0 || D > 18) DIE("decimal scale out of range");
    char out[48]; int o = fmt_fixed(out, v, D);
    char *r = malloc(o ? o : 1); if (!r) { fprintf(stderr, "OOM\n"); at1_fail(3); }
    memcpy(r, out, o); Str s = { (unsigned char *)r, (size_t)o }; return s;
}

/* Per-column bump arena: one growable allocation per numeric column instead of one
 * malloc per value (the decode hot path was ~6M tiny mallocs on a 1.5M-row table).
 * arena_* stash the byte OFFSET in Str.p during the value loop; the caller fixes the
 * offsets up to real pointers once the arena is final (realloc can move base). The
 * arena leaks with the column data, exactly as the per-value buffers did before. */
typedef struct { unsigned char *base; size_t off, cap; } Arena;
static void arena_reserve(Arena *A, size_t need) {
    if (A->off + need > A->cap) {
        size_t nc = A->cap ? A->cap : 4096;
        while (nc < A->off + need) nc <<= 1;
        unsigned char *nb = realloc(A->base, nc);
        if (!nb) { fprintf(stderr, "OOM\n"); at1_fail(3); }
        A->base = nb; A->cap = nc;
    }
}
static Str arena_int(Arena *A, long long v) {
    arena_reserve(A, 24); size_t at = A->off;
    int n = fmt_int((char *)A->base + at, v); A->off += n;
    Str s = { (unsigned char *)(uintptr_t)at, (size_t)n }; return s;   /* .p = offset */
}
static Str arena_fixed(Arena *A, long long v, int D) {
    if (D < 0 || D > 18) DIE("decimal scale out of range");
    arena_reserve(A, 48); size_t at = A->off;
    int n = fmt_fixed((char *)A->base + at, v, D); A->off += n;
    Str s = { (unsigned char *)(uintptr_t)at, (size_t)n }; return s;   /* .p = offset */
}

/* ---------- columnar decode ---------- */
static void columnar_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"), *coltypes = get(S, "coltypes"), *colidx = get(S, "col_index"),
           *values = get(S, "values"), *qmodes = get(S, "quotemodes"), *qbits = get(S, "quotebits"),
           *rowm = get(S, "row_modes"), *fcnt = get(S, "fieldcounts"), *verb = get(S, "verbatim"),
           *hdr = get(S, "header");
    Cur m = { meta->data, 0, meta->len };
    uint64_t nrows = rd_uv(&m);
    if (m.pos + 2 > m.len) DIE("columnar meta");
    int trailing = m.p[m.pos++]; int has_header = m.p[m.pos++];
    uint64_t dl = rd_uv(&m); const unsigned char *delim = rd_bytes(&m, dl);
    uint64_t ncols = rd_uv(&m);
    if (ncols > colidx->len + 1) DIE("columnar ncols");   /* each col has a varint in col_index */

    Str **cols = calloc(ncols ? ncols : 1, sizeof(Str *));
    size_t *colcnt = calloc(ncols ? ncols : 1, sizeof(size_t));
    char **qflag = calloc(ncols ? ncols : 1, sizeof(char *)); /* per-value quoted flag */
    size_t *cursor = calloc(ncols, sizeof(size_t));

    Cur ci = { colidx->data, 0, colidx->len };
    size_t voff = 0, qboff = 0;
    for (uint64_t k = 0; k < ncols; k++) {
        uint64_t clen = rd_uv(&ci);
        if (voff + clen > values->len || clen > values->len) DIE("col data OOB");
        const unsigned char *d = values->data + voff; voff += clen;
        Cur dc = { d, 0, clen };
        if (k >= coltypes->len) DIE("coltypes");
        int t = coltypes->data[k];
        /* count + materialize values */
        Str *vals = NULL; size_t cnt = 0, cap = 0;
        Arena arena = {0}; int use_arena = 0;   /* numeric cols format into one arena, not per-value malloc */
        #define PUSH(s) do { if (cnt==cap){cap=cap?cap*2:16; vals=realloc(vals,cap*sizeof(Str)); \
            if(!vals){fprintf(stderr,"OOM\n");at1_fail(3);}} vals[cnt++]=(s);} while(0)
        if (t == 0) { /* TEXT */
            if (clen == 0) { Str e = { (const unsigned char *)"", 0 }; PUSH(e); }
            else { size_t st = 0; for (size_t i = 0; i <= clen; i++) {
                       if (i == clen || d[i] == '\n') { Str s = { d + st, i - st }; PUSH(s); st = i + 1; } } }
        } else if (t == 1) { /* INT */
            use_arena = 1;
            long long acc = 0; while (dc.pos < dc.len) { acc += rd_sv(&dc); PUSH(arena_int(&arena, acc)); }
        } else if (t == 2) { /* DEC */
            if (dc.pos >= dc.len) DIE("dec empty");
            int D = d[dc.pos++]; long long acc = 0;
            use_arena = 1;
            while (dc.pos < dc.len) { acc += rd_sv(&dc); PUSH(arena_fixed(&arena, acc, D)); }
        } else if (t == 3) { /* NUMEXC */
            if (dc.pos >= dc.len) DIE("numexc empty");
            int sub = d[dc.pos++];
            int D = 0;
            if (sub == 1) { if (dc.pos >= dc.len) DIE("numexc scale"); D = d[dc.pos++]; }
            uint64_t count = rd_uv(&dc);
            if (count > (uint64_t)clen * 8) DIE("numexc count");   /* can't exceed bits available */
            size_t nb = (count + 7) / 8;
            const unsigned char *bits = rd_bytes(&dc, nb);
            uint64_t nexc = rd_uv(&dc);
            if (nexc > count) DIE("numexc nexc");
            Str *excs = malloc((nexc ? nexc : 1) * sizeof(Str));
            for (uint64_t e = 0; e < nexc; e++) { uint64_t el = rd_uv(&dc); const unsigned char *ep = rd_bytes(&dc, el); Str s = { ep, el }; excs[e] = s; }
            long long acc = 0; size_t ei = 0;
            for (uint64_t i = 0; i < count; i++) {
                if (bits[i >> 3] & (1 << (i & 7))) { acc += rd_sv(&dc); PUSH(sub == 0 ? own_int(acc) : own_fixed(acc, D)); }
                else { if (ei >= nexc) DIE("numexc exc"); PUSH(excs[ei++]); }
            }
        } else if (t == 5) { /* DICT: distinct + per-row index */
            uint64_t nvals = rd_uv(&dc), ndict = rd_uv(&dc);
            Str *dv = malloc((ndict ? ndict : 1) * sizeof(Str));
            for (uint64_t i = 0; i < ndict; i++) { uint64_t dl = rd_uv(&dc); const unsigned char *dp = rd_bytes(&dc, dl); dv[i].p = dp; dv[i].n = dl; }
            for (uint64_t i = 0; i < nvals; i++) { uint64_t ix = rd_uv(&dc); if (ix >= ndict) DIE("dict index"); PUSH(dv[ix]); }
            free(dv);
        } else if (t == 6) { /* SHUF: byte-plane shuffled fixed-width ints */
            uint64_t scnt = rd_uv(&dc); long long mn = rd_sv(&dc);
            if (dc.pos >= dc.len) DIE("shuf width"); int W = d[dc.pos++];
            if (W < 1 || W > 8) DIE("shuf width");
            const unsigned char *planes = rd_bytes(&dc, (uint64_t)W * scnt);
            use_arena = 1;
            for (uint64_t i = 0; i < scnt; i++) {
                unsigned long long x = 0;
                for (int p = 0; p < W; p++) x |= (unsigned long long)planes[(size_t)p * scnt + i] << (8 * p);
                PUSH(arena_int(&arena, (long long)x + mn));
            }
        } else if (t == 4) { /* DERIVED */
            uint64_t a = rd_uv(&dc); uint64_t nmap = rd_uv(&dc);
            if (a >= (uint64_t)k) DIE("derived source");   /* source must be an already-materialized column */
            Str *mapv = malloc((nmap ? nmap : 1) * sizeof(Str));
            for (uint64_t j = 0; j < nmap; j++) { uint64_t ml = rd_uv(&dc); const unsigned char *mp = rd_bytes(&dc, ml); Str s = { mp, ml }; mapv[j] = s; }
            /* scan source column, insertion-ordered distinct -> mapv index */
            size_t srcn = colcnt[a]; Str *src = cols[a];
            Str *distinct = malloc((nmap ? nmap : 1) * sizeof(Str)); size_t dn = 0;
            for (size_t i = 0; i < srcn; i++) {
                int found = -1;
                for (size_t q = 0; q < dn; q++)
                    if (distinct[q].n == src[i].n && !memcmp(distinct[q].p, src[i].p, src[i].n)) { found = (int)q; break; }
                if (found < 0) { if ((uint64_t)dn >= nmap) DIE("derived map"); distinct[dn] = src[i]; found = (int)dn; dn++; }
                PUSH(mapv[found]);
            }
            free(distinct);
        }
        /* arena values stored byte offsets; now that arena.base is final, fix to pointers */
        if (use_arena) for (size_t i = 0; i < cnt; i++) vals[i].p = arena.base + (uintptr_t)vals[i].p;
        cols[k] = vals; colcnt[k] = cnt;
        /* quote flags */
        char *fl = malloc(cnt ? cnt : 1);
        if (k >= qmodes->len) DIE("quotemodes");
        int qm = qmodes->data[k];
        if (qm == 0) memset(fl, 0, cnt);
        else if (qm == 1) memset(fl, 1, cnt);
        else { size_t nb = (cnt + 7) / 8;
               if (qboff + nb > qbits->len) DIE("quotebits OOB");
               const unsigned char *bb = qbits->data + qboff; qboff += nb;
               for (size_t i = 0; i < cnt; i++) fl[i] = (bb[i >> 3] >> (i & 7)) & 1; }
        qflag[k] = fl;
        #undef PUSH
    }

    /* assemble rows */
    Cur fc = { fcnt->data, 0, fcnt->len };
    size_t vbi = 0, vb_pos = 0;
    if (has_header && hdr) { buf_put(out, hdr->data, hdr->len); }
    for (uint64_t r = 0; r < nrows; r++) {
        if (r || has_header) buf_putc(out, '\n');
        if (r >= rowm->len) DIE("row_modes");
        if (rowm->data[r] == 0) { /* verbatim line from '\n'-joined stream */
            size_t st = vb_pos; while (vb_pos < verb->len && verb->data[vb_pos] != '\n') vb_pos++;
            buf_put(out, verb->data + st, vb_pos - st); if (vb_pos < verb->len) vb_pos++; vbi++;
        } else {
            uint64_t nf = rd_uv(&fc);
            for (uint64_t i = 0; i < nf; i++) {
                if (i) buf_put(out, delim, dl);
                if (i >= ncols || cursor[i] >= colcnt[i]) DIE("field index");
                Str v = cols[i][cursor[i]]; char q = qflag[i][cursor[i]]; cursor[i]++;
                if (q) { buf_putc(out, '"');
                    for (size_t j = 0; j < v.n; j++) { if (v.p[j] == '"') buf_putc(out, '"'); buf_putc(out, v.p[j]); }
                    buf_putc(out, '"');
                } else buf_put(out, v.p, v.n);
            }
        }
    }
    if (trailing) buf_putc(out, '\n');
    (void)vbi;
}

/* ---------- generic '\n'-split (shared by log/ssh codecs) ---------- */
static Str *split_nl(const unsigned char *p, size_t n, size_t *outn) {
    /* n==0 yields ONE empty cell, never zero: b"" is the join of [""] as much as of
     * [], and only [""] can actually be referenced by the stored counts/ids (the
     * same disambiguation the Python decoders and at1_block.c use). An empty FILE
     * encodes as one empty structured row -- 0 cells here made that DIE("qcol field"). */
    if (n == 0) {
        Str *one = malloc(sizeof(Str)); if (!one) DIE("oom");
        *outn = 1; one->p = p; one->n = 0; return one;
    }
    size_t cnt = 1;
    for (size_t i = 0; i < n; i++) if (p[i] == '\n') cnt++;
    Str *a = malloc(cnt * sizeof(Str)); if (!a) DIE("oom");
    size_t k = 0, st = 0;
    for (size_t i = 0; i <= n; i++)
        if (i == n || p[i] == '\n') { a[k].p = p + st; a[k].n = i - st; k++; st = i + 1; }
    *outn = cnt; return a;
}

/* ---------- log codec (id 3): generic auto-templated logs ---------- */
static void log_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"); Cur m = { meta->data, 0, meta->len };
    uint64_t nlines = rd_uv(&m); if (m.pos >= meta->len) DIE("log meta"); int trailing = m.p[m.pos++];
    size_t nT, nV, nVB;
    Stream *T = get(S, "templates"); Str *tmpl = split_nl(T->data, T->len, &nT);
    Stream *F = get(S, "flags");
    Stream *TI = get(S, "tids"); Cur ti = { TI->data, 0, TI->len };
    Stream *V = get(S, "vars"); Str *vars = split_nl(V->data, V->len, &nV);
    Stream *VB = get(S, "verbatim"); Str *verb = split_nl(VB->data, VB->len, &nVB);
    size_t vi = 0, vbi = 0;
    for (uint64_t li = 0; li < nlines; li++) {
        if (li) buf_putc(out, '\n');
        if (li >= F->len) DIE("log flags");
        if (F->data[li] == 0) { if (vbi >= nVB) DIE("log verbatim"); buf_put(out, verb[vbi].p, verb[vbi].n); vbi++; }
        else {
            uint64_t tid = rd_uv(&ti); if (tid >= nT) DIE("log template"); Str t = tmpl[tid];
            size_t start = 0;
            for (size_t j = 0; j < t.n; j++)
                if (t.p[j] == 0) {  /* marker -> splice next variable token */
                    buf_put(out, t.p + start, j - start); start = j + 1;
                    if (vi >= nV) DIE("log var"); buf_put(out, vars[vi].p, vars[vi].n); vi++;
                }
            buf_put(out, t.p + start, t.n - start);
        }
    }
    if (trailing) buf_putc(out, '\n');
    free(tmpl); free(vars); free(verb);
}

/* ---------- ssh codec (id 0): OpenSSH logs ---------- */
static void ssh_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"); Cur m = { meta->data, 0, meta->len };
    uint64_t nlines = rd_uv(&m); if (m.pos >= m.len) DIE("ssh meta"); int trailing = m.p[m.pos++];
    size_t nT, nMo, nDa, nTi, nHo, nVa, nRm, nVb;
    Str *tmpl = split_nl(get(S, "templates")->data, get(S, "templates")->len, &nT);
    Stream *F = get(S, "flags");
    Str *mo = split_nl(get(S, "months")->data, get(S, "months")->len, &nMo);
    Str *da = split_nl(get(S, "days")->data, get(S, "days")->len, &nDa);
    Str *tm = split_nl(get(S, "times")->data, get(S, "times")->len, &nTi);
    Str *ho = split_nl(get(S, "hosts")->data, get(S, "hosts")->len, &nHo);
    Str *va = split_nl(get(S, "vars")->data, get(S, "vars")->len, &nVa);
    Str *rm = split_nl(get(S, "rawmsgs")->data, get(S, "rawmsgs")->len, &nRm);
    Str *vb = split_nl(get(S, "verbatim")->data, get(S, "verbatim")->len, &nVb);
    Cur pid = { get(S, "pids")->data, 0, get(S, "pids")->len };
    Cur tid = { get(S, "template_ids")->data, 0, get(S, "template_ids")->len };
    size_t ci = 0, vi = 0, ri = 0, vbi = 0;
    char nb[32];
    for (uint64_t li = 0; li < nlines; li++) {
        if (li) buf_putc(out, '\n');
        if (li >= F->len) DIE("ssh flags");
        int f = F->data[li];
        if (f == 0) { if (vbi >= nVb) DIE("ssh verbatim"); buf_put(out, vb[vbi].p, vb[vbi].n); vbi++; continue; }
        if (ci >= nMo || ci >= nDa || ci >= nTi || ci >= nHo) DIE("ssh column");
        buf_put(out, mo[ci].p, mo[ci].n); buf_putc(out, ' ');
        buf_put(out, da[ci].p, da[ci].n); buf_putc(out, ' ');
        buf_put(out, tm[ci].p, tm[ci].n); buf_putc(out, ' ');
        buf_put(out, ho[ci].p, ho[ci].n);
        uint64_t p = rd_uv(&pid); ci++;
        int ln = snprintf(nb, sizeof nb, " sshd[%llu]: ", (unsigned long long)p);
        buf_put(out, nb, ln);
        if (f == 2) {  /* templated: fill '<*>' markers with '\0'-joined vars */
            uint64_t tt = rd_uv(&tid); if (tt >= nT || vi >= nVa) DIE("ssh template"); Str T = tmpl[tt]; Str vl = va[vi]; vi++;
            size_t start = 0, j = 0, vp = 0;
            while (j < T.n) {
                if (j + 2 < T.n && T.p[j] == '<' && T.p[j+1] == '*' && T.p[j+2] == '>') {
                    buf_put(out, T.p + start, j - start);
                    size_t vs = vp; while (vp < vl.n && vl.p[vp] != 0) vp++;
                    buf_put(out, vl.p + vs, vp - vs);
                    if (vp < vl.n) vp++;
                    j += 3; start = j;
                } else j++;
            }
            buf_put(out, T.p + start, T.n - start);
        } else {  /* structured, untemplated message */
            if (ri >= nRm) DIE("ssh rawmsg"); buf_put(out, rm[ri].p, rm[ri].n); ri++;
        }
    }
    if (trailing) buf_putc(out, '\n');
    free(tmpl); free(mo); free(da); free(tm); free(ho); free(va); free(rm); free(vb);
}

/* ---------- json codec (id 1): recursive path-shredding tape ---------- */
typedef struct { Str *lits; size_t nlit; uint64_t *srcs; size_t nsrc; } JRule;
typedef struct {
    Cur tc;                 /* tape cursor (shared across recursion) */
    Str **cols; size_t *cursor; size_t *colcnt; size_t ncol;
    Str *keyvocab; size_t nkeys; JRule *rules; size_t nrules; Str *lastc; Buf *out;
    int depth;
} JCtx;

static void j_emit(JCtx *j) {
    if (++j->depth > 8192) DIE("json nesting depth");
    if (j->tc.pos >= j->tc.len) DIE("json tape end");
    int tok = j->tc.p[j->tc.pos++];
    if (tok == 0) {                       /* LEAF */
        uint64_t cid = rd_uv(&j->tc);
        if (cid >= j->ncol || j->cursor[cid] >= j->colcnt[cid]) DIE("json leaf index");
        Str v = j->cols[cid][j->cursor[cid]++];
        buf_put(j->out, v.p, v.n);
        if (v.n >= 2 && v.p[0] == '"') { j->lastc[cid].p = v.p + 1; j->lastc[cid].n = v.n - 2; }
        else j->lastc[cid] = v;
    } else if (tok == 3) {                /* DERIVED: literals interleaved with sources */
        uint64_t rid = rd_uv(&j->tc); if (rid >= j->nrules) DIE("json rule id"); JRule *r = &j->rules[rid];
        buf_putc(j->out, '"');
        for (size_t i = 0; i < r->nsrc; i++) {
            buf_put(j->out, r->lits[i].p, r->lits[i].n);
            if (r->srcs[i] >= j->ncol) DIE("json rule src");
            Str c = j->lastc[r->srcs[i]]; buf_put(j->out, c.p, c.n);
        }
        buf_put(j->out, r->lits[r->nsrc].p, r->lits[r->nsrc].n);
        buf_putc(j->out, '"');
    } else if (tok == 1) {                /* OBJECT */
        uint64_t nk = rd_uv(&j->tc); buf_putc(j->out, '{');
        for (uint64_t i = 0; i < nk; i++) {
            if (i) buf_putc(j->out, ',');
            uint64_t kid = rd_uv(&j->tc);
            if (kid >= j->nkeys) DIE("json key id");
            buf_put(j->out, j->keyvocab[kid].p, j->keyvocab[kid].n); buf_putc(j->out, ':');
            j_emit(j);
        }
        buf_putc(j->out, '}');
    } else if (tok == 2) {                /* ARRAY */
        uint64_t n = rd_uv(&j->tc); buf_putc(j->out, '[');
        for (uint64_t i = 0; i < n; i++) { if (i) buf_putc(j->out, ','); j_emit(j); }
        buf_putc(j->out, ']');
    } else DIE("json tape token");
    j->depth--;
}

static void json_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"); Cur m = { meta->data, 0, meta->len };
    uint64_t n_lines = rd_uv(&m); if (m.pos >= meta->len) DIE("json meta"); int trailing = m.p[m.pos] == 1;
    Stream *F = get(S, "flags");
    size_t nkeys, nVb;
    Str *keyvocab = split_nl(get(S, "keyvocab")->data, get(S, "keyvocab")->len, &nkeys);
    Str *verb = split_nl(get(S, "verbatim")->data, get(S, "verbatim")->len, &nVb);

    /* rules */
    Cur rb = { get(S, "rules")->data, 0, get(S, "rules")->len };
    uint64_t nrules = rd_uv(&rb); if (nrules > rb.len) DIE("json nrules");
    JRule *rules = malloc((nrules ? nrules : 1) * sizeof(JRule));
    for (uint64_t i = 0; i < nrules; i++) {
        uint64_t nlit = rd_uv(&rb); if (nlit > rb.len) DIE("json nlit"); rules[i].nlit = nlit; rules[i].lits = malloc((nlit ? nlit : 1) * sizeof(Str));
        for (uint64_t k = 0; k < nlit; k++) { uint64_t ll = rd_uv(&rb); rules[i].lits[k].p = rd_bytes(&rb, ll); rules[i].lits[k].n = ll; }
        uint64_t nsrc = rd_uv(&rb); if (nsrc > rb.len) DIE("json nsrc"); rules[i].nsrc = nsrc; rules[i].srcs = malloc((nsrc ? nsrc : 1) * sizeof(uint64_t));
        for (uint64_t k = 0; k < nsrc; k++) rules[i].srcs[k] = rd_uv(&rb);
    }

    /* columns from value_index + values blob (cols joined with a 1-byte sep) */
    Stream *valst = get(S, "values");
    Cur vi = { get(S, "value_index")->data, 0, get(S, "value_index")->len };
    uint64_t ncol = rd_uv(&vi); if (ncol > vi.len) DIE("json ncol");
    size_t *clen = malloc((ncol ? ncol : 1) * sizeof(size_t));
    for (uint64_t k = 0; k < ncol; k++) clen[k] = rd_uv(&vi);
    const unsigned char *vb = valst->data; size_t off = 0;
    Str **cols = malloc((ncol ? ncol : 1) * sizeof(Str *)); size_t *colcnt = malloc((ncol ? ncol : 1) * sizeof(size_t));
    size_t *cursor = calloc(ncol ? ncol : 1, sizeof(size_t)); Str *lastc = calloc(ncol ? ncol : 1, sizeof(Str));
    for (uint64_t k = 0; k < ncol; k++) {
        if (off + clen[k] > valst->len) DIE("json values OOB");
        cols[k] = split_nl(vb + off, clen[k], &colcnt[k]);
        off += clen[k] + (k < ncol - 1 ? 1 : 0);
    }

    JCtx j; j.cols = cols; j.cursor = cursor; j.colcnt = colcnt; j.ncol = ncol;
    j.keyvocab = keyvocab; j.nkeys = nkeys; j.rules = rules; j.nrules = nrules; j.lastc = lastc; j.out = out; j.depth = 0;
    Stream *T = get(S, "tape"); j.tc.p = T->data; j.tc.len = T->len; j.tc.pos = 0;

    size_t vbi = 0;
    for (uint64_t li = 0; li < n_lines; li++) {
        if (li) buf_putc(out, '\n');
        if (li >= F->len) DIE("json flags");
        if (F->data[li] == 0) { if (vbi >= nVb) DIE("json verbatim"); buf_put(out, verb[vbi].p, verb[vbi].n); vbi++; j.depth = 0; }
        else { j.depth = 0; j_emit(&j); }
    }
    if (trailing) buf_putc(out, '\n');
}

/* ---------- osm codec (id 2): columnar OSM XML ---------- */
#include <time.h>
static void put_lit(Buf *b, const char *s) { buf_put(b, s, strlen(s)); }
static void put_ll(Buf *b, long long v) {
    char t[24]; int n = 0; int neg = v < 0;
    unsigned long long a = neg ? -(unsigned long long)v : (unsigned long long)v;
    if (neg) t[n++] = '-';
    n += u64toa(a, t + n); buf_put(b, t, n);
}
static void put_u(Buf *b, uint64_t v) { char t[24]; int n = u64toa((unsigned long long)v, t); buf_put(b, t, n); }
static void put_coord(Buf *b, long long q) {     /* q/1e7 %.7f, strip trailing 0 then . */
    char t[32]; int n = snprintf(t, sizeof t, "%.7f", (double)q / 1e7);
    while (n > 0 && t[n-1] == '0') n--;
    if (n > 0 && t[n-1] == '.') n--;
    if (n == 0) buf_putc(b, '0'); else buf_put(b, t, n);
}
static void put_ts(Buf *b, long long epoch) {
    time_t tt = (time_t)epoch; struct tm g;
#if defined(_WIN32)
    gmtime_s(&g, &tt);
#else
    gmtime_r(&tt, &g);
#endif
    char t[32]; size_t n = strftime(t, sizeof t, "%Y-%m-%dT%H:%M:%SZ", &g); buf_put(b, t, n);
}
static Str *decode_vocab2(const unsigned char *d, size_t len, size_t *outn) {
    Cur c = { d, 0, len }; uint64_t n = rd_uv(&c);
    if (n > len) DIE("vocab count");                 /* each item needs >=1 byte + NUL */
    Str *a = malloc((n ? n : 1) * sizeof(Str));
    for (uint64_t i = 0; i < n; i++) { size_t st = c.pos; while (c.pos < len && d[c.pos] != 0) c.pos++;
        if (c.pos >= len) DIE("vocab unterminated");
        a[i].p = d + st; a[i].n = c.pos - st; c.pos++; }
    *outn = n; return a;
}

static void osm_decode(Streams *S, Buf *out) {
    if (get(S, "meta")->len < 1) DIE("osm meta");
    int trailing = get(S, "meta")->data[0] == 1;
    Stream *OP = get(S, "opcodes");
    size_t nTK, nRO;
    Str *tagk = decode_vocab2(get(S, "tag_keys")->data, get(S, "tag_keys")->len, &nTK);
    Str *roles = decode_vocab2(get(S, "roles")->data, get(S, "roles")->len, &nRO);
    #define CUR(nm) (Cur){ get(S,nm)->data, 0, get(S,nm)->len }
    Cur n_id=CUR("n_id"),n_ver=CUR("n_ver"),n_ts=CUR("n_ts"),n_lat=CUR("n_lat"),n_lon=CUR("n_lon"),
        n_tc=CUR("n_tagcnt"),n_tk=CUR("n_tagkey"),n_tv=CUR("n_tagval"),
        w_id=CUR("w_id"),w_ver=CUR("w_ver"),w_ts=CUR("w_ts"),w_nc=CUR("w_ndcnt"),w_nr=CUR("w_ndref"),
        w_tc=CUR("w_tagcnt"),w_tk=CUR("w_tagkey"),w_tv=CUR("w_tagval"),
        r_id=CUR("r_id"),r_ver=CUR("r_ver"),r_ts=CUR("r_ts"),r_mc=CUR("r_memcnt"),r_mt=CUR("r_memtype"),
        r_mr=CUR("r_memref"),r_mo=CUR("r_memrole"),r_tc=CUR("r_tagcnt"),r_tk=CUR("r_tagkey"),r_tv=CUR("r_tagval");
    Cur vb = CUR("verbatim");
    long long ni=0,nts=0,la=0,lo=0, wi=0,wts=0,nd=0, ri=0,rts=0,mref=0;
    const char *MT[3] = { "node", "way", "relation" };
    int first = 1;
    Stream *tvS=get(S,"n_tagval"), *wtvS=get(S,"w_tagval"), *rtvS=get(S,"r_tagval");

    /* emit one element's tags (already read counts) given the tag streams */
    #define EMIT_TAGS(cnt,tkc,tvc,tvbuf) do { for(uint64_t _i=0;_i<cnt;_i++){ \
        uint64_t kid=rd_uv(&tkc); uint64_t vl=rd_uv(&tvc); \
        if(kid>=nTK) DIE("osm tag key"); if(tvc.pos+vl>(tvbuf)->len || vl>(tvbuf)->len) DIE("osm tag val"); \
        buf_putc(out,'\n'); put_lit(out,"    <tag k=\""); buf_put(out,tagk[kid].p,tagk[kid].n); \
        put_lit(out,"\" v=\""); buf_put(out,(tvbuf)->data+tvc.pos,vl); tvc.pos+=vl; put_lit(out,"\"/>"); } } while(0)

    for (size_t e = 0; e < OP->len; e++) {
        int op = OP->data[e];
        if (op == 0) { uint64_t bl = rd_uv(&vb); if (!first) buf_putc(out, '\n'); first = 0;
            const unsigned char *bp = rd_bytes(&vb, bl); buf_put(out, bp, bl); continue; }
        if (!first) buf_putc(out, '\n'); first = 0;
        if (op == 1) {
            ni += rd_sv(&n_id); uint64_t ver = rd_uv(&n_ver); nts += rd_sv(&n_ts);
            la += rd_sv(&n_lat); lo += rd_sv(&n_lon); uint64_t tc = rd_uv(&n_tc);
            put_lit(out,"  <node id=\""); put_ll(out,ni); put_lit(out,"\" version=\""); put_u(out,ver);
            put_lit(out,"\" timestamp=\""); put_ts(out,nts); put_lit(out,"\" lat=\""); put_coord(out,la);
            put_lit(out,"\" lon=\""); put_coord(out,lo); buf_putc(out,'"');
            if (tc==0) put_lit(out,"/>");
            else { buf_putc(out,'>'); EMIT_TAGS(tc,n_tk,n_tv,tvS); buf_putc(out,'\n'); put_lit(out,"  </node>"); }
        } else if (op == 2) {
            wi += rd_sv(&w_id); uint64_t ver = rd_uv(&w_ver); wts += rd_sv(&w_ts); uint64_t ndc = rd_uv(&w_nc);
            if (ndc > w_nr.len) DIE("osm ndcount");          /* each nd reads >=1 byte */
            long long nds[1]; (void)nds; uint64_t tc;
            /* read nds into temp then tags (must know if empty for /> ) */
            long long *ndarr = malloc((ndc?ndc:1)*sizeof(long long));
            for (uint64_t i=0;i<ndc;i++){ nd += rd_sv(&w_nr); ndarr[i]=nd; }
            tc = rd_uv(&w_tc);
            put_lit(out,"  <way id=\""); put_ll(out,wi); put_lit(out,"\" version=\""); put_u(out,ver);
            put_lit(out,"\" timestamp=\""); put_ts(out,wts); buf_putc(out,'"');
            if (ndc==0 && tc==0) put_lit(out,"/>");
            else { buf_putc(out,'>');
                for(uint64_t i=0;i<ndc;i++){ buf_putc(out,'\n'); put_lit(out,"    <nd ref=\""); put_ll(out,ndarr[i]); put_lit(out,"\"/>"); }
                EMIT_TAGS(tc,w_tk,w_tv,wtvS); buf_putc(out,'\n'); put_lit(out,"  </way>"); }
            free(ndarr);
        } else { /* relation */
            ri += rd_sv(&r_id); uint64_t ver = rd_uv(&r_ver); rts += rd_sv(&r_ts); uint64_t mc = rd_uv(&r_mc);
            if (mc > r_mt.len) DIE("osm memcount");           /* each member reads >=1 byte */
            /* read members */
            uint64_t *mtp=malloc((mc?mc:1)*sizeof(uint64_t)); long long *mrf=malloc((mc?mc:1)*sizeof(long long)); uint64_t *mro=malloc((mc?mc:1)*sizeof(uint64_t));
            for(uint64_t i=0;i<mc;i++){ mtp[i]=rd_uv(&r_mt); if(mtp[i]>=3) DIE("osm memtype"); mref+=rd_sv(&r_mr); mrf[i]=mref; mro[i]=rd_uv(&r_mo); if(mro[i]>=nRO) DIE("osm memrole"); }
            uint64_t tc = rd_uv(&r_tc);
            put_lit(out,"  <relation id=\""); put_ll(out,ri); put_lit(out,"\" version=\""); put_u(out,ver);
            put_lit(out,"\" timestamp=\""); put_ts(out,rts); buf_putc(out,'"');
            if (mc==0 && tc==0) put_lit(out,"/>");
            else { buf_putc(out,'>');
                for(uint64_t i=0;i<mc;i++){ buf_putc(out,'\n'); put_lit(out,"    <member type=\""); put_lit(out,MT[mtp[i]]);
                    put_lit(out,"\" ref=\""); put_ll(out,mrf[i]); put_lit(out,"\" role=\""); buf_put(out,roles[mro[i]].p,roles[mro[i]].n); put_lit(out,"\"/>"); }
                EMIT_TAGS(tc,r_tk,r_tv,rtvS); buf_putc(out,'\n'); put_lit(out,"  </relation>"); }
            free(mtp); free(mrf); free(mro);
        }
    }
    if (trailing) buf_putc(out, '\n');
}

/* ---------- vcf codec (id 5): sparse genotype matrix ---------- */
static void vcf_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"); Cur m = { meta->data, 0, meta->len };
    uint64_t nlines = rd_uv(&m); if (m.pos >= m.len) DIE("vcf meta"); int trailing = m.p[m.pos++];
    uint64_t nsamp = rd_uv(&m); if (m.pos >= m.len) DIE("vcf meta"); int pos_delta = m.p[m.pos++];
    uint64_t rl = rd_uv(&m); const unsigned char *rp = rd_bytes(&m, rl); Str ref_tok = { rp, rl };
    uint64_t nvoc = rd_uv(&m); if (nvoc > m.len) DIE("vcf vocab count");
    Str *vocab = malloc((nvoc ? nvoc : 1) * sizeof(Str));
    for (uint64_t i = 0; i < nvoc; i++) { uint64_t gl = rd_uv(&m); const unsigned char *gp = rd_bytes(&m, gl); vocab[i].p = gp; vocab[i].n = gl; }

    Stream *F = get(S, "flags");
    const char *names[9] = { "chrom","pos","id","ref","alt","qual","filter","info","format" };
    Str *cols[9]; size_t ncol[9];
    Str *posv = NULL; size_t nposv = 0;
    for (int c = 0; c < 9; c++) {
        Stream *st = get(S, names[c]);
        if (c == 1 && pos_delta) {  /* POS delta-coded -> rebuild decimal strings */
            Cur pc = { st->data, 0, st->len }; long long acc = 0; size_t cap = 16; nposv = 0;
            posv = malloc(cap * sizeof(Str));
            while (pc.pos < pc.len) { acc += rd_sv(&pc); if (nposv == cap) { cap *= 2; posv = realloc(posv, cap * sizeof(Str)); if (!posv) { fprintf(stderr, "OOM\n"); at1_fail(3); } } posv[nposv++] = own_int(acc); }
            cols[1] = posv; ncol[1] = nposv;
        } else { cols[c] = split_nl(st->data, st->len, &ncol[c]); }
    }
    size_t nVb; Str *vb = split_nl(get(S, "verbatim")->data, get(S, "verbatim")->len, &nVb);
    Cur gt = { get(S, "gt")->data, 0, get(S, "gt")->len };

    Str *samples = malloc((nsamp ? nsamp : 1) * sizeof(Str));
    size_t ci = 0, vbi = 0;
    for (uint64_t li = 0; li < nlines; li++) {
        if (li) buf_putc(out, '\n');
        if (li >= F->len) DIE("vcf flags");
        if (F->data[li] == 0) { if (vbi >= nVb) DIE("vcf verbatim"); buf_put(out, vb[vbi].p, vb[vbi].n); vbi++; continue; }
        for (uint64_t i = 0; i < nsamp; i++) samples[i] = ref_tok;
        uint64_t nz = rd_uv(&gt), idx = 0;
        for (uint64_t k = 0; k < nz; k++) { idx += rd_uv(&gt); uint64_t tid = rd_uv(&gt); if (idx >= nsamp || tid >= nvoc) DIE("vcf genotype"); samples[idx] = vocab[tid]; }
        for (int c = 0; c < 9; c++) { if ((size_t)ci >= ncol[c]) DIE("vcf column"); buf_put(out, cols[c][ci].p, cols[c][ci].n); buf_putc(out, '\t'); }
        ci++;
        for (uint64_t i = 0; i < nsamp; i++) { buf_put(out, samples[i].p, samples[i].n); if (i + 1 < nsamp) buf_putc(out, '\t'); }
    }
    if (trailing) buf_putc(out, '\n');
    free(vocab); free(samples); free(vb);
    for (int c = 0; c < 9; c++) if (!(c == 1 && pos_delta)) free(cols[c]);
    free(posv);
}

/* ---------- jsondoc codec (id 6): whole-document JSON skeleton + value shred ---------- */
static void jsondoc_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta");
    if (meta->len >= 1 && meta->data[0] == 0) {   /* raw mode: file stored verbatim */
        Stream *r = get(S, "raw"); buf_put(out, r->data, r->len); return;
    }
    Stream *skel = get(S, "skeleton"), *colids = get(S, "colids"),
           *vi = get(S, "value_index"), *vals = get(S, "values");
    Cur ic = { vi->data, 0, vi->len };
    uint64_t ncol = rd_uv(&ic); if (ncol > vi->len) DIE("jsondoc ncol");
    Str **cols = calloc(ncol ? ncol : 1, sizeof(Str *));
    size_t *ccnt = calloc(ncol ? ncol : 1, sizeof(size_t));
    size_t *ccur = calloc(ncol ? ncol : 1, sizeof(size_t));
    size_t voff = 0;
    for (uint64_t c = 0; c < ncol; c++) {
        uint64_t ln = rd_uv(&ic);
        if (voff + ln > vals->len) DIE("jsondoc values OOB");
        cols[c] = split_nl(vals->data + voff, ln, &ccnt[c]); voff += ln;
    }
    Cur cc = { colids->data, 0, colids->len };
    for (size_t i = 0; i < skel->len; i++) {
        unsigned char b = skel->data[i];
        if (b == 0) {
            uint64_t cid = rd_uv(&cc);
            if (cid >= ncol || ccur[cid] >= ccnt[cid]) DIE("jsondoc index");
            Str v = cols[cid][ccur[cid]++];
            buf_put(out, v.p, v.n);
        } else buf_putc(out, b);
    }
    for (uint64_t c = 0; c < ncol; c++) free(cols[c]);
    free(cols); free(ccnt); free(ccur);
}

#if defined(_OPENMP) && !defined(AT1_NO_XZ)
/* ---------- soft-fail decode for worker threads ----------
 * In the multithreaded path, the per-block decode runs on OpenMP worker threads.
 * at1_fail() either longjmps (library mode) or exit()s — and longjmp across threads
 * is undefined behaviour — so workers must never call it. These variants mirror the
 * normal decoders exactly but return NULL on any error; the caller raises the error
 * on the MAIN thread after the parallel region (where DIE/longjmp is safe again).
 * All bounds validation already happened on the main thread (the index pre-scan), so
 * the only failure reachable here is a corrupt compressed payload or OOM. */
static unsigned char *xz_decode_nofail(const unsigned char *in, size_t in_len, size_t *out_len) {
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&s, UINT64_MAX, 0) != LZMA_OK) return NULL;
    if (in_len > (SIZE_MAX - 4096) / 4) { lzma_end(&s); return NULL; }
    size_t cap = in_len * 4 + 4096; unsigned char *out = malloc(cap);
    if (!out) { lzma_end(&s); return NULL; }
    s.next_in = in; s.avail_in = in_len; s.next_out = out; s.avail_out = cap;
    for (;;) {
        lzma_ret r = lzma_code(&s, LZMA_FINISH);
        if (r == LZMA_STREAM_END) break;
        if (r != LZMA_OK) { free(out); lzma_end(&s); return NULL; }
        if (s.avail_out == 0) {
            if (cap >= AT1_MAX_DECODE) { free(out); lzma_end(&s); return NULL; }
            size_t used = cap;
            cap = (cap > AT1_MAX_DECODE / 2) ? AT1_MAX_DECODE : cap << 1;
            unsigned char *n = realloc(out, cap);
            if (!n) { free(out); lzma_end(&s); return NULL; }
            out = n; s.next_out = out + used; s.avail_out = cap - used;
        }
    }
    *out_len = cap - s.avail_out; lzma_end(&s); return out;
}
static unsigned char *zstd_decode_nofail(const unsigned char *in, size_t in_len, size_t *out_len) {
    unsigned long long sz = ZSTD_getFrameContentSize(in, in_len);
    if (sz == ZSTD_CONTENTSIZE_ERROR || sz == ZSTD_CONTENTSIZE_UNKNOWN) return NULL;
    if (sz > AT1_MAX_DECODE) return NULL;
    unsigned char *out = malloc(sz ? sz : 1); if (!out) return NULL;
    size_t r = ZSTD_decompress(out, sz, in, in_len);
    if (ZSTD_isError(r)) { free(out); return NULL; }
    *out_len = r; return out;
}
static unsigned char *backend_decode_nofail(int backend, const unsigned char *in, size_t in_len, size_t *out_len) {
    if (backend == B_ZSTD) return zstd_decode_nofail(in, in_len, out_len);
    if (backend == B_STORED) {
        unsigned char *o = malloc(in_len ? in_len : 1); if (!o) return NULL;
        memcpy(o, in, in_len); *out_len = in_len; return o;
    }
    return xz_decode_nofail(in, in_len, out_len);
}
/* like split_nl but returns NULL on OOM instead of crashing. n==0 yields ONE empty
 * cell, exactly like split_nl -- the MT path must stay byte-identical to serial,
 * and an empty file (one empty structured row) is valid input, not an error. */
static Str *split_nl_nofail(const unsigned char *p, size_t n, size_t *outn) {
    if (n == 0) {
        Str *one = malloc(sizeof(Str)); if (!one) return NULL;
        *outn = 1; one->p = p; one->n = 0; return one;
    }
    size_t cnt = 1;
    for (size_t i = 0; i < n; i++) if (p[i] == '\n') cnt++;
    Str *a = malloc(cnt * sizeof(Str)); if (!a) return NULL;
    size_t k = 0, st = 0;
    for (size_t i = 0; i <= n; i++)
        if (i == n || p[i] == '\n') { a[k].p = p + st; a[k].n = i - st; k++; st = i + 1; }
    *outn = cnt; return a;
}
#endif /* _OPENMP && !AT1_NO_XZ */

/* ---------- qcolumnar codec (id 7): queryable columnar -- full reconstruction.
   (Random-access query is a separate API; this path rebuilds the whole file.)
   Per-(group,column) blocks are LZMA-compressed, so this codec requires the xz
   backend and is compiled out of an AT1_NO_XZ build (e.g. WASM).
   With -fopenmp, row-group blocks are decoded in parallel (windowed, bounded memory)
   and assembled serially in row order — byte-identical to the single-thread path,
   which remains the reference when OpenMP is off. ---------- */
#ifndef AT1_NO_XZ
static void qcolumnar_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"); Cur m = { meta->data, 0, meta->len };
    uint64_t nlines = rd_uv(&m); if (m.pos >= m.len) DIE("qcol meta"); int trailing = m.p[m.pos++];
    uint64_t dl = rd_uv(&m); const unsigned char *delim = rd_bytes(&m, dl);
    uint64_t ncols = rd_uv(&m), rg = rd_uv(&m);
    uint64_t n_struct = rd_uv(&m); (void)rd_uv(&m);   /* n_struct (MT path); nrg unused */
#ifndef _OPENMP
    (void)n_struct;
#endif
    if (ncols > meta->len || rg == 0) DIE("qcol meta");
    const unsigned char *coltypes = rd_bytes(&m, ncols);

    Stream *RM = get(S, "row_modes");
    size_t nVb; Str *vb = split_nl(get(S, "verbatim")->data, get(S, "verbatim")->len, &nVb);
    Cur idx = { get(S, "index")->data, 0, get(S, "index")->len };
    Stream *blk = get(S, "blocks"); size_t blkoff = 0;

#ifdef _OPENMP
    /* ===== multithreaded path (opt-in: -fopenmp) — decode a window of row-group
       blocks in parallel, then assemble that window's rows serially in row order.
       Byte-identical to the serial #else path; that path stays the reference. ===== */
    uint64_t ngroups = (rg && n_struct) ? (n_struct + rg - 1) / rg : 0;
    typedef struct { int btag; const unsigned char *bp; size_t bl; } BDesc;
    BDesc *desc = NULL;
    if (ngroups) {                 /* pre-scan the index on the MAIN thread: every
                                      bounds check / DIE happens here, never on a worker */
        if (ngroups > (uint64_t)blk->len + 1) DIE("qcol groups");
        if (ncols && ngroups > SIZE_MAX / ncols / sizeof(BDesc)) DIE("qcol groups");
        desc = malloc(ngroups * ncols * sizeof(BDesc)); if (!desc) DIE("qcol alloc");
        for (uint64_t gg = 0; gg < ngroups; gg++)
            for (uint64_t c = 0; c < ncols; c++) {
                uint64_t clen = rd_uv(&idx);
                if (coltypes[c] == 1) { (void)rd_sv(&idx); (void)rd_sv(&idx); }
                else if (coltypes[c] == 2) { (void)rd_bytes(&idx, 16); }
                if (blkoff + clen > blk->len || clen > blk->len || clen < 1) DIE("qcol block OOB");
                BDesc *bd = &desc[gg * ncols + c];
                bd->btag = blk->data[blkoff]; bd->bp = blk->data + blkoff + 1; bd->bl = (size_t)clen - 1;
                blkoff += clen;
            }
    }
    int W = 4 * omp_get_max_threads(); if (W < 1) W = 1; if (W > 256) W = 256;
    if (ngroups && (uint64_t)W > ngroups) W = (int)ngroups;
    size_t wslots = (size_t)W * (ncols ? ncols : 1);
    Str **wcv = calloc(wslots, sizeof(Str *));
    size_t *wcvn = calloc(wslots, sizeof(size_t));
    unsigned char **wdbuf = calloc(wslots, sizeof(unsigned char *));
    if (!wcv || !wcvn || !wdbuf) DIE("qcol alloc");
    long win_base = 0; int loaded = 0; uint64_t si = 0; size_t vbi = 0;
    for (uint64_t li = 0; li < nlines; li++) {
        if (li) buf_putc(out, '\n');
        if (li >= RM->len) DIE("qcol row_modes");
        if (RM->data[li] == 0) { if (vbi >= nVb) DIE("qcol verbatim"); buf_put(out, vb[vbi].p, vb[vbi].n); vbi++; continue; }
        long g = (long)(si / rg);
        if (!loaded || g < win_base || g >= win_base + W) {
            for (size_t i = 0; i < wslots; i++) { free(wcv[i]); free(wdbuf[i]); wcv[i] = NULL; wdbuf[i] = NULL; wcvn[i] = 0; }
            win_base = (g / W) * W; loaded = 1;
            uint64_t wgroups = ((uint64_t)win_base + W <= ngroups) ? (uint64_t)W : (ngroups - (uint64_t)win_base);
            long nblk = (long)(wgroups * ncols);
            int derr = 0;
            #pragma omp parallel for schedule(dynamic) reduction(|:derr)
            for (long j = 0; j < nblk; j++) {
                uint64_t gg = (uint64_t)win_base + (uint64_t)j / ncols, c = (uint64_t)j % ncols;
                BDesc *bd = &desc[gg * ncols + c];
                size_t ol = 0; unsigned char *d = backend_decode_nofail(bd->btag == 1 ? B_ZSTD : B_XZ, bd->bp, bd->bl, &ol);
                if (!d) { derr = 1; continue; }
                size_t cnt = 0; Str *lines = split_nl_nofail(d, ol, &cnt);
                if (!lines && ol > 0) { free(d); derr = 1; continue; }
                size_t slot = (gg - (uint64_t)win_base) * ncols + c;
                wdbuf[slot] = d; wcv[slot] = lines; wcvn[slot] = cnt;
            }
            if (derr) DIE("qcol block decode");
        }
        uint64_t rng = si % rg;
        size_t base = (size_t)(g - win_base) * ncols;
        size_t rowlen = 0;
        for (uint64_t c = 0; c < ncols; c++) {
            if (rng >= wcvn[base + c]) DIE("qcol field");
            rowlen += wcv[base + c][rng].n;
        }
        if (ncols) rowlen += (size_t)(ncols - 1) * dl;
        buf_reserve(out, rowlen);
        unsigned char *w = out->p + out->n;
        for (uint64_t c = 0; c < ncols; c++) {
            if (c) { if (dl == 1) *w++ = delim[0]; else { memcpy(w, delim, dl); w += dl; } }
            size_t n = wcv[base + c][rng].n; memcpy(w, wcv[base + c][rng].p, n); w += n;
        }
        out->n += rowlen;
        si++;
    }
    if (trailing) buf_putc(out, '\n');
    for (size_t i = 0; i < wslots; i++) { free(wcv[i]); free(wdbuf[i]); }
    free(wcv); free(wcvn); free(wdbuf); free(desc); free(vb);
#else
    Str **cv = calloc(ncols ? ncols : 1, sizeof(Str *));
    size_t *cvn = calloc(ncols ? ncols : 1, sizeof(size_t));
    unsigned char **dbuf = calloc(ncols ? ncols : 1, sizeof(unsigned char *));
    long cur_g = -1; uint64_t si = 0; size_t vbi = 0;

    for (uint64_t li = 0; li < nlines; li++) {
        if (li) buf_putc(out, '\n');
        if (li >= RM->len) DIE("qcol row_modes");
        if (RM->data[li] == 0) { if (vbi >= nVb) DIE("qcol verbatim"); buf_put(out, vb[vbi].p, vb[vbi].n); vbi++; continue; }
        long g = (long)(si / rg);
        if (g != cur_g) {
#ifdef AT1_PROFILE
            clock_t _tr = clock();
#endif
            for (uint64_t c = 0; c < ncols; c++) { free(cv[c]); free(dbuf[c]); cv[c] = NULL; dbuf[c] = NULL; }
            for (uint64_t c = 0; c < ncols; c++) {
                uint64_t clen = rd_uv(&idx);
                if (coltypes[c] == 1) { (void)rd_sv(&idx); (void)rd_sv(&idx); }   /* skip int zone map */
                else if (coltypes[c] == 2) { (void)rd_bytes(&idx, 16); }              /* skip decimal zone map (2x f64) */
                if (blkoff + clen > blk->len || clen > blk->len || clen < 1) DIE("qcol block OOB");
                /* each block is self-describing: 1-byte codec tag (0=xz,1=zstd) + payload */
                int btag = blk->data[blkoff];
                const unsigned char *bp = blk->data + blkoff + 1;
                size_t bl = (size_t)clen - 1;
                blkoff += clen;
                size_t ol; unsigned char *d = backend_decode(btag == 1 ? B_ZSTD : B_XZ, bp, bl, &ol);
                dbuf[c] = d; cv[c] = split_nl(d, ol, &cvn[c]);
            }
            cur_g = g;
#ifdef AT1_PROFILE
            g_prof_refresh_secs += (double)(clock() - _tr) / CLOCKS_PER_SEC;
#endif
        }
        uint64_t rng = si % rg;
        /* assemble the row with one reserve + raw copies instead of 2*ncols buf_put
         * calls (each a function call + bounds branch). Byte-identical; this is the
         * qcol decode hot path (~46% of decode was per-field call overhead). */
        size_t rowlen = 0;
        for (uint64_t c = 0; c < ncols; c++) {
            if (rng >= cvn[c]) DIE("qcol field");
            rowlen += cv[c][rng].n;
        }
        if (ncols) rowlen += (size_t)(ncols - 1) * dl;
        buf_reserve(out, rowlen);
        unsigned char *w = out->p + out->n;
        for (uint64_t c = 0; c < ncols; c++) {
            if (c) { if (dl == 1) *w++ = delim[0]; else { memcpy(w, delim, dl); w += dl; } }
            size_t n = cv[c][rng].n; memcpy(w, cv[c][rng].p, n); w += n;
        }
        out->n += rowlen;
        si++;
    }
    if (trailing) buf_putc(out, '\n');
    for (uint64_t c = 0; c < ncols; c++) { free(cv[c]); free(dbuf[c]); }
    free(cv); free(cvn); free(dbuf); free(vb);
#endif
}

/* ---------- qjson codec (id 8): queryable NDJSON -- full reconstruction.
   Like qcolumnar, but a structured row is rebuilt by interleaving a per-row
   template (ncols+1 literal segments) with its ncols scalar values:
   seg[0] + val[0] + seg[1] + ... + seg[ncols]. Blocks are best-of(xz,zstd). ---------- */
static void qjson_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"); Cur m = { meta->data, 0, meta->len };
    uint64_t nlines = rd_uv(&m); if (m.pos >= m.len) DIE("qjson meta"); int trailing = m.p[m.pos++];
    uint64_t ncols = rd_uv(&m), rg = rd_uv(&m); (void)rd_uv(&m); (void)rd_uv(&m); /* n_struct, nrg */
    if (ncols > meta->len || rg == 0) DIE("qjson meta");
    const unsigned char *coltypes = rd_bytes(&m, ncols);

    /* template: nseg (== ncols+1) length-prefixed literal segments */
    Stream *tpl = get(S, "template"); Cur tc = { tpl->data, 0, tpl->len };
    uint64_t nseg = rd_uv(&tc);
    if (nseg != ncols + 1) DIE("qjson template");
    Str *seg = calloc(nseg ? nseg : 1, sizeof(Str));
    if (!seg) { fprintf(stderr, "qjson alloc\n"); at1_fail(3); }
    for (uint64_t i = 0; i < nseg; i++) {
        uint64_t sl = rd_uv(&tc);
        seg[i].p = rd_bytes(&tc, sl); seg[i].n = sl;
    }

    Stream *RM = get(S, "row_modes");
    size_t nVb; Str *vb = split_nl(get(S, "verbatim")->data, get(S, "verbatim")->len, &nVb);
    Cur idx = { get(S, "index")->data, 0, get(S, "index")->len };
    Stream *blk = get(S, "blocks"); size_t blkoff = 0;

    Str **cv = calloc(ncols ? ncols : 1, sizeof(Str *));
    size_t *cvn = calloc(ncols ? ncols : 1, sizeof(size_t));
    unsigned char **dbuf = calloc(ncols ? ncols : 1, sizeof(unsigned char *));
    long cur_g = -1; uint64_t si = 0; size_t vbi = 0;

    for (uint64_t li = 0; li < nlines; li++) {
        if (li) buf_putc(out, '\n');
        if (li >= RM->len) DIE("qjson row_modes");
        if (RM->data[li] == 0) { if (vbi >= nVb) DIE("qjson verbatim"); buf_put(out, vb[vbi].p, vb[vbi].n); vbi++; continue; }
        long g = (long)(si / rg);
        if (g != cur_g) {
            for (uint64_t c = 0; c < ncols; c++) { free(cv[c]); free(dbuf[c]); cv[c] = NULL; dbuf[c] = NULL; }
            for (uint64_t c = 0; c < ncols; c++) {
                uint64_t clen = rd_uv(&idx);
                if (coltypes[c] == 1) { (void)rd_sv(&idx); (void)rd_sv(&idx); }   /* skip int zone map */
                else if (coltypes[c] == 2) { (void)rd_bytes(&idx, 16); }              /* skip decimal zone map (2x f64) */
                if (blkoff + clen > blk->len || clen > blk->len || clen < 1) DIE("qjson block OOB");
                int btag = blk->data[blkoff];
                const unsigned char *bp = blk->data + blkoff + 1;
                size_t bl = (size_t)clen - 1;
                blkoff += clen;
                size_t ol; unsigned char *d = backend_decode(btag == 1 ? B_ZSTD : B_XZ, bp, bl, &ol);
                dbuf[c] = d; cv[c] = split_nl(d, ol, &cvn[c]);
            }
            cur_g = g;
        }
        uint64_t rng = si % rg;
        for (uint64_t c = 0; c < ncols; c++) {
            buf_put(out, seg[c].p, seg[c].n);
            if (rng >= cvn[c]) DIE("qjson field");
            buf_put(out, cv[c][rng].p, cv[c][rng].n);
        }
        buf_put(out, seg[ncols].p, seg[ncols].n);
        si++;
    }
    if (trailing) buf_putc(out, '\n');
    for (uint64_t c = 0; c < ncols; c++) { free(cv[c]); free(dbuf[c]); }
    free(cv); free(cvn); free(dbuf); free(vb); free(seg);
}
#endif /* AT1_NO_XZ */

/* ---------- dicom codec (id 9): metadata/pixel split + byte-level pixel transform ----------
   The metadata skeleton (pre/suf) is stored verbatim; the native pixel-data region is
   re-transformed by a reversible byte-level transform. Image-codec pixel data
   (decode_class=1, JPEG2000/JPEG-LS) is NOT decodable here -- it needs the Python decoder;
   we reject it with a defined error rather than mis-decode. (See AT1_FORMAT_SPEC.md.) */
static void dicom_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta");
    if (meta->len >= 1 && meta->data[0] == 0) {          /* verbatim whole file */
        Stream *r = get(S, "raw"); buf_put(out, r->data, r->len); return;
    }
    if (meta->len < 1 || meta->data[0] != 1) DIE("dicom meta mode");
    Cur m = { meta->data, 1, meta->len };
    if (m.pos + 2 > meta->len) DIE("dicom meta header");
    int tid = meta->data[m.pos++];
    int dc  = meta->data[m.pos++];
    uint64_t rows = rd_uv(&m), cols = rd_uv(&m), samples = rd_uv(&m),
             bits = rd_uv(&m), padlen = rd_uv(&m);
    (void)rows;
    if (m.pos + padlen > meta->len) DIE("dicom pad OOB");
    const unsigned char *pad = meta->data + m.pos;       /* padlen bytes */
    Stream *pre = get(S, "pre"), *suf = get(S, "suf"), *pix = get(S, "pix");
    if (dc != 0) {                                        /* image codec -> Python only */
        fprintf(stderr, "dicom: image-codec pixel data (decode_class=1) requires the Python decoder\n");
        at1_fail(2);
    }
    buf_put(out, pre->data, pre->len);
    size_t bw = (bits == 8) ? 1 : 2;                     /* mirror the encoder's dtype choice */
    uint32_t mask = (bits == 8) ? 0xFFu : 0xFFFFu;
    if (tid != 0) {
        /* A non-raw transform must describe exactly the bytes present. Validate the pixel
           count (overflow-safe) and pix length up front so a malformed meta rejects cleanly
           instead of emitting wrong bytes. Valid files satisfy pix->len == pixels*bw. */
        uint64_t pixels = rows;
        if (cols && pixels > UINT64_MAX / cols) DIE("dicom shape overflow");
        pixels *= cols;
        if (samples && pixels > UINT64_MAX / samples) DIE("dicom shape overflow");
        pixels *= samples;
        if (bw && pixels > UINT64_MAX / bw) DIE("dicom shape overflow");
        if (pixels * bw != pix->len) DIE("dicom pixel size mismatch");
    }
    if (tid == 0) {                                      /* raw */
        buf_put(out, pix->data, pix->len);
    } else if (tid == 3) {                               /* byte-plane: hi[n] then lo[n], 16-bit LE */
        size_t n = pix->len / 2;
        const unsigned char *hi = pix->data, *lo = pix->data + n;
        for (size_t i = 0; i < n; i++) { buf_putc(out, lo[i]); buf_putc(out, hi[i]); }
    } else if (tid == 1 || tid == 2) {                   /* horizontal / vertical modular delta */
        uint64_t w = cols * samples;
        if (w == 0) DIE("dicom width");
        size_t nelem = pix->len / bw;
        if (nelem % w != 0) DIE("dicom shape");
        uint32_t *col = NULL, acc = 0;
        if (tid == 2) { col = calloc((size_t)w, sizeof(uint32_t)); if (!col) DIE("OOM"); }
        for (size_t i = 0; i < nelem; i++) {
            uint32_t d = (bw == 2) ? (uint32_t)(pix->data[2*i] | (pix->data[2*i+1] << 8))
                                   : (uint32_t)pix->data[i];
            size_t c = (size_t)(i % w);
            uint32_t val;
            if (tid == 1) { if (c == 0) acc = 0; acc = (acc + d) & mask; val = acc; }
            else          { col[c] = (col[c] + d) & mask; val = col[c]; }
            if (bw == 2) { buf_putc(out, val & 0xFF); buf_putc(out, (val >> 8) & 0xFF); }
            else buf_putc(out, val & 0xFF);
        }
        free(col);
    } else {
        DIE("dicom: unknown pixel transform id");
    }
    buf_put(out, pad, padlen);
    buf_put(out, suf->data, suf->len);
}

/* embed (id 10): float/tensor .npy. meta=[width][hlen][header][n]; data=byte-split element bytes.
   Reconstruct the original .npy = header + byte-unsplit(data): out[e*width+b] = data[b*n+e]. */
static void embed_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"), *data = get(S, "data");
    Cur m = { meta->data, 0, meta->len };
    uint64_t width = rd_uv(&m);
    uint64_t hlen = rd_uv(&m);
    if (m.pos + hlen > meta->len) DIE("embed header OOB");
    const unsigned char *header = meta->data + m.pos; m.pos += (size_t)hlen;
    uint64_t n = rd_uv(&m);
    if (width == 0 || width > 32) DIE("embed width");
    if (n && width > (uint64_t)SIZE_MAX / n) DIE("embed size overflow");
    if ((size_t)(width * n) != data->len) DIE("embed data length mismatch");
    buf_put(out, header, (size_t)hlen);
    size_t dl = (size_t)(width * n);
    unsigned char *tmp = malloc(dl ? dl : 1); if (!tmp) DIE("embed oom");
    for (uint64_t b = 0; b < width; b++)
        for (uint64_t e = 0; e < n; e++)
            tmp[(size_t)(e * width + b)] = data->data[(size_t)(b * n + e)];
    buf_put(out, tmp, dl);
    free(tmp);
}

/* ---------- qjson2 (id 11, EXPERIMENTAL): multi-template NDJSON ----------
 * Streams: meta = varint nlines, u8 trailing, varint ntemplates; 'line_map' = one
 * varint per line (0 = verbatim, k+1 = template k); 'verbatim'; plus each template's
 * complete v1-qjson streams namespaced "t{i}:meta" etc. Decode each template with
 * the EXISTING qjson decoder over a filtered Streams view, split into lines, and
 * interleave back in original order (see lossless_qjson2.py).
 * Depends on qjson_decode, so it shares qjson's AT1_NO_XZ exclusion. */
#ifndef AT1_NO_XZ
static void qjson2_decode(Streams *S, Buf *out) {
    Stream *meta = get(S, "meta"); Cur m = { meta->data, 0, meta->len };
    uint64_t nlines = rd_uv(&m);
    if (m.pos >= m.len) DIE("qjson2 meta");
    int trailing = m.p[m.pos++];
    uint64_t nt = rd_uv(&m);
    if (nt > 64) DIE("qjson2 templates");
    Buf *tbuf = calloc(nt ? nt : 1, sizeof(Buf));
    Str **tl = calloc(nt ? nt : 1, sizeof(Str *));
    size_t *tn = calloc(nt ? nt : 1, sizeof(size_t));
    size_t *tcur = calloc(nt ? nt : 1, sizeof(size_t));
    if (!tbuf || !tl || !tn || !tcur) DIE("oom");
    for (uint64_t i = 0; i < nt; i++) {
        char pre[16]; int pl = snprintf(pre, sizeof pre, "t%llu:", (unsigned long long)i);
        Streams sub; sub.n = 0;
        for (int k = 0; k < S->n; k++)
            if (!strncmp(S->s[k].name, pre, (size_t)pl)) {
                Stream *dst = &sub.s[sub.n++];
                *dst = S->s[k];
                memmove(dst->name, dst->name + pl, strlen(dst->name + pl) + 1);
            }
        qjson_decode(&sub, &tbuf[i]);
        tl[i] = split_nl(tbuf[i].p, tbuf[i].n, &tn[i]);
    }
    size_t nvb; Stream *VB = get(S, "verbatim");
    Str *verb = split_nl(VB->data, VB->len, &nvb);
    Stream *LM = get(S, "line_map"); Cur lm = { LM->data, 0, LM->len };
    size_t vi = 0;
    for (uint64_t li = 0; li < nlines; li++) {
        uint64_t k = rd_uv(&lm);
        Str *cell;
        if (k == 0) { if (vi >= nvb) DIE("qjson2 verbatim"); cell = &verb[vi++]; }
        else {
            uint64_t t = k - 1;
            if (t >= nt || tcur[t] >= tn[t]) DIE("qjson2 line_map");
            cell = &tl[t][tcur[t]++];
        }
        buf_put(out, cell->p, cell->n);
        if (li + 1 < nlines) buf_putc(out, '\n');
    }
    if (trailing && nlines) buf_putc(out, '\n');
    for (uint64_t i = 0; i < nt; i++) { free(tbuf[i].p); free(tl[i]); }
    free(tbuf); free(tl); free(tn); free(tcur); free(verb);
}
#endif /* AT1_NO_XZ */

static void run_codec(int codec, Streams *S, Buf *out) {
    if (codec == 4) columnar_decode(S, out);
    else if (codec == 3) log_decode(S, out);
    else if (codec == 0) ssh_decode(S, out);
    else if (codec == 1) json_decode(S, out);
    else if (codec == 2) osm_decode(S, out);
    else if (codec == 5) vcf_decode(S, out);
    else if (codec == 6) jsondoc_decode(S, out);
    else if (codec == 9) dicom_decode(S, out);
    else if (codec == 10) embed_decode(S, out);
#ifndef AT1_NO_XZ
    else if (codec == 7) qcolumnar_decode(S, out);
    else if (codec == 8) qjson_decode(S, out);
    else if (codec == 11) qjson2_decode(S, out);
#else
    else if (codec == 7 || codec == 8 || codec == 11) { fprintf(stderr, "queryable codec %d needs the xz backend, absent in this build\n", codec); at1_fail(3); }
#endif
    else if (codec == 12) {
        /* a bundle extracts to MULTIPLE files: supported by this binary's CLI (output
         * treated as a directory) but not by the single-buffer library API. */
        fprintf(stderr, "bundle (codec 12) extracts many files -- not available via the "
                        "single-buffer API; use the CLI with a directory output\n");
        at1_fail(2);
    }
    else { fprintf(stderr, "codec id %d not implemented (0-10, RAW=255)\n", codec); at1_fail(2); }
}

/* ---------- top level ---------- */
static void decode_container(const unsigned char *blob, size_t len, Buf *out);

static void decode_whole(const unsigned char *blob, size_t len, Buf *out) {
    int codec = blob[4];
    if (codec == 255) {
        if (len < 6) { fprintf(stderr, "truncated raw\n"); at1_fail(2); }
        size_t ol; unsigned char *o = backend_decode(blob[5], blob + 6, len - 6, &ol); buf_put(out, o, ol); free(o); return;
    }
    Streams S; if (!unpack(blob + 5, len - 5, &S)) { fprintf(stderr, "bad container\n"); at1_fail(2); }
    run_codec(codec, &S, out);
}

static void decode_stream(const unsigned char *blob, size_t len, Buf *out) {
    int codec = blob[4]; Cur c = { blob, 5, len };
    (void)rd_uv(&c); /* chunk_lines */
    while (c.pos < len) {
        uint64_t plen = rd_uv(&c);
        if (plen < 1 || plen > len - c.pos) { fprintf(stderr, "bad frame\n"); at1_fail(2); }
        const unsigned char *payload = c.p + c.pos; c.pos += plen;
        int method = payload[0];
        if (method == 1) {
            if (plen < 2) { fprintf(stderr, "bad frame\n"); at1_fail(2); }
            size_t ol; unsigned char *o = backend_decode(payload[1], payload + 2, plen - 2, &ol); buf_put(out, o, ol); free(o);
        } else {
            Streams S; if (!unpack(payload + 1, plen - 1, &S)) { fprintf(stderr, "bad frame\n"); at1_fail(2); }
            run_codec(codec, &S, out);
        }
    }
}

/* Optional integrity trailer: sha256(original) (32) + INTEG_MAGIC (4). It sits
   after the container; strip it so RAW/stream payloads parse on their real length.
   (This decoder strips and ignores the hash; the Python reference verifies it.) */
#define AT1_INTEG_LEN 36
static const unsigned char AT1_INTEG_MAGIC[4] = { 0xA1, 'S', '6', 0x01 };
static void decode_container(const unsigned char *blob, size_t len, Buf *out) {
    const unsigned char *expect = NULL;          /* embedded sha256(original), if present */
    if (len >= AT1_INTEG_LEN &&
        !memcmp(blob + len - 4, AT1_INTEG_MAGIC, 4)) {
        expect = blob + len - AT1_INTEG_LEN;     /* 32-byte hash precedes the 4-byte magic */
        len -= AT1_INTEG_LEN;
    }
    if (len < 5) { fprintf(stderr, "truncated\n"); at1_fail(2); }
    if (!memcmp(blob, "AT1\x03", 4)) decode_stream(blob, len, out);
    else if (!memcmp(blob, "AT1\x02", 4)) decode_whole(blob, len, out);
    else { fprintf(stderr, "bad magic\n"); at1_fail(2); }
    if (expect) {                                /* verify decode == original, like the Python ref */
        Sha256 c; unsigned char got[32];
        sha256_init(&c); sha256_update(&c, out->p, out->n); sha256_final(&c, got);
        if (memcmp(got, expect, 32) != 0) {
            fprintf(stderr, "integrity check failed: decoded bytes do not match embedded SHA-256\n");
            free(out->p); out->p = NULL; out->n = out->cap = 0;   /* never hand back unverified output */
            at1_fail(2);
        }
    }
}

/* ---------- public library ABI (see at1_decode.h) ---------- */
#define AT1_OK 0
#define AT1_ERR_CORRUPT 2   /* malformed/hostile input rejected */
#define AT1_ERR_BACKEND 3   /* resource/backend (xz/zstd/OOM) error */

int at1_decode_buffer(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    if (!in || !out || !out_len) return AT1_ERR_CORRUPT;
    Buf b = {0};
    g_at1_in_lib = 1; g_at1_err = 0;
    if (setjmp(g_at1_errjmp)) {            /* a decode path called at1_fail() */
        free(b.p); g_at1_in_lib = 0;
        return g_at1_err ? g_at1_err : AT1_ERR_CORRUPT;
    }
    decode_container(in, in_len, &b);
    g_at1_in_lib = 0;
    *out = b.p; *out_len = b.n;
    return AT1_OK;
}
void at1_free(uint8_t *p) { free(p); }
const char *at1_version(void) { return "AT-1 reference decoder 0.1.0"; }

#ifndef AT1_NO_MAIN
/* ---------- bundle (id 12): many files in one .at1, CLI extraction ----------
 * Streams: 'manifest' = JSON [{"name": ..., ...}, ...]; 'e{i}' = entry i's complete
 * inner .at1 (decoded recursively via decode_container, which re-verifies the inner
 * SHA-256 trailer). Entry names: forward-slash relpaths; we reject absolutes, '..'
 * segments, backslashes/escapes and drive colons (zip-slip). */
#ifdef _WIN32
#include <direct.h>
#define at1_mkdir(p) _mkdir(p)
#else
#include <sys/stat.h>
#define at1_mkdir(p) mkdir(p, 0777)
#endif

static int manifest_name(const unsigned char *j, size_t n, int idx, char *out, size_t cap) {
    /* idx-th occurrence of "name": "..." in the manifest JSON (entries are written in
     * order; names with JSON escapes are rejected -- the encoder writes plain paths) */
    const char *key = "\"name\":";
    int seen = -1; size_t i = 0;
    while (i + 8 < n) {
        if (!memcmp(j + i, key, 7)) {
            size_t k = i + 7;
            while (k < n && (j[k] == ' ')) k++;
            if (k < n && j[k] == '"') {
                k++; size_t st = k;
                while (k < n && j[k] != '"' && j[k] != '\\') k++;
                if (k >= n || j[k] == '\\') return 0;        /* escape/EOF: reject */
                if (++seen == idx) {
                    if (k - st >= cap) return 0;
                    memcpy(out, j + st, k - st); out[k - st] = 0; return 1;
                }
                i = k;
            }
        }
        i++;
    }
    return 0;
}

static int name_unsafe(const char *s) {
    if (!*s || *s == '/' || strchr(s, '\\') || strchr(s, ':')) return 1;
    for (const char *p = s; *p; ) {                       /* any '..' path segment */
        const char *e = strchr(p, '/'); size_t L = e ? (size_t)(e - p) : strlen(p);
        if (L == 0 || (L == 2 && p[0] == '.' && p[1] == '.')) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

static int bundle_extract(const unsigned char *blob, size_t len, const char *outdir) {
    Streams S;
    if (len < 5 || !unpack(blob + 5, len - 5, &S)) { fprintf(stderr, "bad bundle\n"); return 2; }
    Stream *man = get(&S, "manifest");
    at1_mkdir(outdir);                                     /* best-effort; may exist */
    int n = 0;
    for (;; n++) {
        char ename[16]; snprintf(ename, sizeof ename, "e%d", n);
        Stream *e = get(&S, ename);
        if (e->len == 0) break;
        char name[512];
        if (!manifest_name(man->data, man->len, n, name, sizeof name) || name_unsafe(name)) {
            fprintf(stderr, "bundle: bad/unsafe entry name (entry %d)\n", n); return 2;
        }
        char path[1024];
        int pn = snprintf(path, sizeof path, "%s/%s", outdir, name);
        if (pn < 0 || (size_t)pn >= sizeof path) {
            /* truncation would also put strlen(outdir)+1 past the buffer below */
            fprintf(stderr, "bundle: output path too long (entry %d)\n", n); return 2;
        }
        for (char *p = path + strlen(outdir) + 1; *p; p++)  /* mkdir -p the parents */
            if (*p == '/') { *p = 0; at1_mkdir(path); *p = '/'; }
        Buf b = {0};
        decode_container(e->data, e->len, &b);             /* inner trailer re-verified */
        FILE *o = fopen(path, "wb");
        if (!o || fwrite(b.p, 1, b.n, o) != b.n) { fprintf(stderr, "bundle: write %s\n", path); return 1; }
        fclose(o); free(b.p);
        fprintf(stderr, "  = %s (%zu bytes)\n", name, b.n);
    }
    fprintf(stderr, "bundle: extracted %d entries -> %s\n", n, outdir);
    return n ? 0 : 2;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s input.at1 output  (bundles: output is a directory)\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb"); if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *blob = malloc(sz); if (fread(blob, 1, sz, f) != (size_t)sz) { perror("read"); return 1; }
    fclose(f);
    if (sz >= 5 && !memcmp(blob, "AT1\x02", 4) && blob[4] == 12)
        return bundle_extract(blob, (size_t)sz, argv[2]);   /* bundles have no outer trailer */
#ifdef AT1_PROFILE
    clock_t _tw = clock();
    Buf out = {0}; decode_container(blob, sz, &out);
    double _tot = (double)(clock() - _tw) / CLOCKS_PER_SEC;
    double _xf = _tot - g_prof_backend_secs;
    double _split = g_prof_refresh_secs - g_prof_backend_secs;   /* split_nl ≈ refresh − backend */
    double _asm = _xf - (_split > 0 ? _split : 0);               /* assembly ≈ transforms − split_nl */
    fprintf(stderr,
        "[profile] total %.3fs  backend(xz/zstd) %.3fs (%.1f%%)  our-transforms %.3fs (%.1f%%)\n"
        "[profile] decoded %.2f MB at %.1f MB/s overall  (transforms alone: %.1f MB/s)\n",
        _tot, g_prof_backend_secs, 100.0 * g_prof_backend_secs / _tot,
        _xf, 100.0 * _xf / _tot,
        out.n / 1e6, (out.n / 1e6) / _tot, _xf > 0 ? (out.n / 1e6) / _xf : 0.0);
    if (g_prof_refresh_secs > 0)
        fprintf(stderr,
            "[profile] qcol breakdown: split_nl ~%.3fs (%.1f%%)  row-assembly ~%.3fs (%.1f%%)\n",
            _split, 100.0 * _split / _tot, _asm, 100.0 * _asm / _tot);
#else
    Buf out = {0}; decode_container(blob, sz, &out);
#endif
    FILE *g = fopen(argv[2], "wb"); if (!g) { perror("out"); return 1; }
    fwrite(out.p, 1, out.n, g); fclose(g);
    fprintf(stderr, "wrote %zu bytes\n", out.n);
    fprintf(stderr, "AT1_STATS original=%ld compressed=%zu io=%ld\n", (long)out.n, (size_t)sz, (long)sz);
    return 0;
}
#endif /* AT1_NO_MAIN */
