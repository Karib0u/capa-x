/* Driver: calls every function with values the compiler cannot fold, so each
 * one stays live and is called with the source's arguments. Never run on the
 * host; the binaries are only decompiled. */
#include <stdio.h>
#include "ks.h"

static volatile int v = 3;
static volatile double vd = 2.5;
static volatile intptr_t sink;

static int sub(int a, int b) { return a - b; }

int main(int argc, char **argv) {
    int a = v + argc, b = v * 2;
    int arr[16];
    char text[] = "hello world";
    struct ks_point p = {a, b}, q = {b, a};
    struct ks_node n3 = {3, 0}, n2 = {2, &n3}, n1 = {1, &n2};
    struct ks_big big, copy;
    int m[4][4] = {{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}, {13, 14, 15, 16}};
    int qo, ro;

    sink += ks_add3(a, b, argc) + ks_udiv(a, b) + ks_sdiv(-a, b) + ks_smod(-a, b);
    sink += ks_sar(-a, b) + ks_shr(a, b) + ks_rotl(a, b) + ks_bswap(a) + ks_popcount(a);
    sink += ks_mul64(a, b) + ks_div64(a, b) + ks_udiv64(a, b) + ks_shl64(a, b);
    sink += ks_sign_char((signed char)a) + ks_zero_uchar((unsigned char)a) + ks_ret_short(a);
    sink += ks_is_even(a) + ks_clamp(a, 0, b) + ks_abs(-a) + ks_min_u_vs_s(a, -b);
    sink += ks_eight(a, b, 1, 2, 3, 4, 5, 6) + ks_mix_widths((char)a, (short)b, a, b);
    sink += (intptr_t)(ks_fma_d(vd, vd, a) + ks_avg_f((float)vd, 1.0f) + ks_i2d(a));
    sink += ks_d2i(vd) + (intptr_t)ks_mixed_fp(a, vd, b, (float)vd);
    sink += ks_hash_fnv(a, b) + ks_collatz(a) + ks_gcd(a, b) + ks_fact(a) + ks_fib_iter(a);
    sink += ks_switch_dense(a) + ks_switch_sparse(b) + ks_nested_loops(a, b) + ks_goto_cleanup(a, -b);
    sink += ks_stdcall3(a, b, argc) + ks_fastcall3(a, b, argc);

    ks_fill(arr, 16, a);
    sink += ks_sum_array(arr, 16) + ks_strlen(argv[0]) + ks_strcmp(argv[0], text);
    ks_reverse(text);
    sink += ks_point_dot(p, q) + ks_point_add(p, q).y;
    big = ks_big_make(a);
    ks_copy_struct(&copy, &big);
    sink += (intptr_t)ks_big_sum(&copy) + ks_list_sum(&n1) + (intptr_t)ks_list_find(&n1, a);
    sink += ks_apply(sub, a, b) + ks_sum_varargs(4, a, b, 5, 6) + ks_bump() + ks_lookup(a);
    sink += (intptr_t)ks_name_of(a) + ks_count_char(text, 'l') + ks_matrix_trace(m) + ks_big_frame(a);
    ks_out_params(a, &qo, &ro);
    sink += qo + ro;

    if (argc > 5) {
        sink += ks_message(text) + (intptr_t)ks_resolve("user32.dll", "MessageBeep");
        sink += ks_tick_delta() + ks_write_file("out.bin", text, sizeof text);
        ks_die("bye");
    }
    printf("%ld\n", (long)sink);
    return 0;
}
