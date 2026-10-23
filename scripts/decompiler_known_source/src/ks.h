/* Known-source corpus: every function here has a prototype and a meaning we know.
 * KS keeps each function out of line and its ABI as written (no clones, no
 * dropped arguments), so the binary's functions match the source one to one. */
#ifndef KS_H
#define KS_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__clang__)
#define KS __attribute__((noinline, used))
#else
#define KS __attribute__((noipa, used))
#endif

#if defined(_WIN32) && !defined(_WIN64)
#define KS_STDCALL __attribute__((stdcall))
#define KS_FASTCALL __attribute__((fastcall))
#else
#define KS_STDCALL
#define KS_FASTCALL
#endif

/* arith.c: pure scalar functions, also run by the differential test */
int ks_add3(int a, int b, int c);
unsigned ks_udiv(unsigned a, unsigned b);
int ks_sdiv(int a, int b);
int ks_smod(int a, int b);
int ks_sar(int a, int n);
unsigned ks_shr(unsigned a, int n);
unsigned ks_rotl(unsigned x, int n);
unsigned ks_bswap(unsigned x);
int ks_popcount(unsigned x);
int64_t ks_mul64(int64_t a, int64_t b);
int64_t ks_div64(int64_t a, int64_t b);
uint64_t ks_udiv64(uint64_t a, uint64_t b);
uint64_t ks_shl64(uint64_t a, int n);
int ks_sign_char(signed char c);
unsigned ks_zero_uchar(unsigned char c);
short ks_ret_short(int x);
_Bool ks_is_even(int x);
int ks_clamp(int x, int lo, int hi);
int ks_abs(int x);
int ks_min_u_vs_s(unsigned a, int b);
int ks_eight(int a, int b, int c, int d, int e, int f, int g, int h);
int64_t ks_mix_widths(char a, short b, int c, int64_t d);
double ks_fma_d(double a, double b, double c);
float ks_avg_f(float a, float b);
int ks_d2i(double d);
double ks_i2d(int i);
double ks_mixed_fp(int a, double b, int c, float d);
uint32_t ks_hash_fnv(uint32_t seed, uint32_t x);
int ks_collatz(unsigned n);
int ks_gcd(int a, int b);
int ks_fact(int n);
int ks_fib_iter(int n);
int ks_switch_dense(int x);
int ks_switch_sparse(int x);
int ks_nested_loops(int n, int m);
int ks_goto_cleanup(int a, int b);
int KS_STDCALL ks_stdcall3(int a, int b, int c);
int KS_FASTCALL ks_fastcall3(int a, int b, int c);

/* data.c: memory, structs, strings, callbacks, varargs */
struct ks_point { int x, y; };
struct ks_big { int a[6]; double d; };
struct ks_node { int value; struct ks_node *next; };
typedef int (*ks_binop)(int, int);

extern int ks_counter;
extern const int ks_table[8];
extern const char *const ks_names[4];

int ks_sum_array(const int *a, int n);
void ks_fill(int *a, int n, int v);
int ks_strlen(const char *s);
int ks_strcmp(const char *a, const char *b);
void ks_reverse(char *s);
int ks_point_dot(struct ks_point p, struct ks_point q);
struct ks_point ks_point_add(struct ks_point p, struct ks_point q);
struct ks_big ks_big_make(int seed);
double ks_big_sum(const struct ks_big *b);
int ks_list_sum(const struct ks_node *n);
struct ks_node *ks_list_find(struct ks_node *n, int v);
int ks_apply(ks_binop f, int a, int b);
int ks_sum_varargs(int count, ...);
int ks_vsum(int count, va_list ap);
int ks_bump(void);
int ks_lookup(int i);
const char *ks_name_of(int i);
int ks_count_char(const char *s, char c);
void ks_copy_struct(struct ks_big *dst, const struct ks_big *src);
int ks_matrix_trace(int m[4][4]);
int ks_big_frame(int seed);
void ks_out_params(int x, int *q, int *r);

/* win.c: Windows API use */
int ks_message(const char *text);
void *ks_resolve(const char *dll, const char *fn);
unsigned ks_tick_delta(void);
int ks_write_file(const char *path, const void *buf, unsigned len);
__attribute__((noreturn)) void ks_die(const char *why);

#endif
