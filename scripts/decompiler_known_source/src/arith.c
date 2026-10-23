#include "ks.h"

KS int ks_add3(int a, int b, int c) { return a + b * 3 - c; }
KS unsigned ks_udiv(unsigned a, unsigned b) { return b ? a / b : 0xFFFFFFFFu; }
KS int ks_sdiv(int a, int b) { return b ? a / b : -1; }
KS int ks_smod(int a, int b) { return b ? a % b : 0; }
KS int ks_sar(int a, int n) { return a >> (n & 31); }
KS unsigned ks_shr(unsigned a, int n) { return a >> (n & 31); }
KS unsigned ks_rotl(unsigned x, int n) { n &= 31; return (x << n) | (x >> ((32 - n) & 31)); }
KS unsigned ks_bswap(unsigned x) {
    return (x >> 24) | ((x >> 8) & 0xFF00u) | ((x << 8) & 0xFF0000u) | (x << 24);
}
KS int ks_popcount(unsigned x) {
    int n = 0;
    while (x) { x &= x - 1; n++; }
    return n;
}
KS int64_t ks_mul64(int64_t a, int64_t b) { return a * b + 7; }
KS int64_t ks_div64(int64_t a, int64_t b) { return b ? a / b : 0; }
KS uint64_t ks_udiv64(uint64_t a, uint64_t b) { return b ? a / b + a % b : 0; }
KS uint64_t ks_shl64(uint64_t a, int n) { return a << (n & 63); }
KS int ks_sign_char(signed char c) { return c * 2; }
KS unsigned ks_zero_uchar(unsigned char c) { return c + 1000u; }
KS short ks_ret_short(int x) { return (short)(x * 3); }
KS _Bool ks_is_even(int x) { return (x & 1) == 0; }
KS int ks_clamp(int x, int lo, int hi) { return x < lo ? lo : x > hi ? hi : x; }
KS int ks_abs(int x) { return x < 0 ? -x : x; }
/* The comparison is unsigned: (unsigned)b is compared, a classic sign trap. */
KS int ks_min_u_vs_s(unsigned a, int b) { return a < (unsigned)b ? 1 : 2; }
KS int ks_eight(int a, int b, int c, int d, int e, int f, int g, int h) {
    return a - b + c * d - e + f * g - h;
}
KS int64_t ks_mix_widths(char a, short b, int c, int64_t d) { return a + b * 2 + c * 4 + d * 8; }
KS double ks_fma_d(double a, double b, double c) { return a * b + c; }
KS float ks_avg_f(float a, float b) { return (a + b) * 0.5f; }
KS int ks_d2i(double d) { return (int)d; }
KS double ks_i2d(int i) { return i / 4.0; }
KS double ks_mixed_fp(int a, double b, int c, float d) { return a * b - c / (double)d; }
KS uint32_t ks_hash_fnv(uint32_t seed, uint32_t x) {
    uint32_t h = seed ^ 0x811C9DC5u;
    for (int i = 0; i < 4; i++) { h ^= (x >> (i * 8)) & 0xFF; h *= 0x01000193u; }
    return h;
}
KS int ks_collatz(unsigned n) {
    int steps = 0;
    while (n > 1 && steps < 1000) { n = (n & 1) ? 3 * n + 1 : n / 2; steps++; }
    return steps;
}
KS int ks_gcd(int a, int b) { return b == 0 ? a : ks_gcd(b, a % b); }
KS int ks_fact(int n) { return n <= 1 ? 1 : n * ks_fact(n - 1); }
KS int ks_fib_iter(int n) {
    int a = 0, b = 1;
    for (int i = 0; i < n; i++) { int t = a + b; a = b; b = t; }
    return a;
}
KS int ks_switch_dense(int x) {
    switch (x) {
    case 0: return 11;
    case 1: return 23;
    case 2: return 37;
    case 3: return 41;
    case 4: return 59;
    case 5: return 67;
    case 6: return 73;
    case 7: return 89;
    default: return -1;
    }
}
KS int ks_switch_sparse(int x) {
    switch (x) {
    case 3: return 1;
    case 100: return 2;
    case 1000: return 3;
    case -5: return 4;
    case 65536: return 5;
    default: return 0;
    }
}
KS int ks_nested_loops(int n, int m) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (i == 7) continue;
        for (int j = 0; j < m; j++) {
            if (j > i) break;
            s += i ^ j;
        }
    }
    return s;
}
KS int ks_goto_cleanup(int a, int b) {
    int r = 0;
    if (a < 0) goto fail;
    r += a;
    if (b < 0) goto fail;
    r += b;
    return r;
fail:
    return -r - 1;
}
KS int KS_STDCALL ks_stdcall3(int a, int b, int c) { return a * 100 + b * 10 + c; }
KS int KS_FASTCALL ks_fastcall3(int a, int b, int c) { return a * 100 - b * 10 + c; }
