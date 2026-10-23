#include "ks.h"

int ks_counter = 5;
const int ks_table[8] = {2, 3, 5, 7, 11, 13, 17, 19};
const char *const ks_names[4] = {"alpha", "bravo", "charlie", "delta"};

KS int ks_sum_array(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}
KS void ks_fill(int *a, int n, int v) {
    for (int i = 0; i < n; i++) a[i] = v + i;
}
KS int ks_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (int)(p - s);
}
KS int ks_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
KS void ks_reverse(char *s) {
    int n = ks_strlen(s);
    for (int i = 0; i < n / 2; i++) { char t = s[i]; s[i] = s[n - 1 - i]; s[n - 1 - i] = t; }
}
KS int ks_point_dot(struct ks_point p, struct ks_point q) { return p.x * q.x + p.y * q.y; }
KS struct ks_point ks_point_add(struct ks_point p, struct ks_point q) {
    struct ks_point r = {p.x + q.x, p.y + q.y};
    return r;
}
KS struct ks_big ks_big_make(int seed) {
    struct ks_big b;
    for (int i = 0; i < 6; i++) b.a[i] = seed * (i + 1);
    b.d = seed / 3.0;
    return b;
}
KS double ks_big_sum(const struct ks_big *b) {
    double s = b->d;
    for (int i = 0; i < 6; i++) s += b->a[i];
    return s;
}
KS int ks_list_sum(const struct ks_node *n) {
    int s = 0;
    for (; n; n = n->next) s += n->value;
    return s;
}
KS struct ks_node *ks_list_find(struct ks_node *n, int v) {
    while (n && n->value != v) n = n->next;
    return n;
}
KS int ks_apply(ks_binop f, int a, int b) { return f(a, b) + 1; }
KS int ks_vsum(int count, va_list ap) {
    int s = 0;
    for (int i = 0; i < count; i++) s += va_arg(ap, int);
    return s;
}
KS int ks_sum_varargs(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int s = ks_vsum(count, ap);
    va_end(ap);
    return s;
}
KS int ks_bump(void) { return ++ks_counter; }
KS int ks_lookup(int i) { return ks_table[i & 7]; }
KS const char *ks_name_of(int i) { return (i >= 0 && i < 4) ? ks_names[i] : "unknown"; }
KS int ks_count_char(const char *s, char c) {
    int n = 0;
    for (; *s; s++) n += *s == c;
    return n;
}
KS void ks_copy_struct(struct ks_big *dst, const struct ks_big *src) { *dst = *src; }
KS int ks_matrix_trace(int m[4][4]) {
    int t = 0;
    for (int i = 0; i < 4; i++) t += m[i][i];
    return t;
}
/* More than a page of locals: the compiler emits a stack probe call. */
KS int ks_big_frame(int seed) {
    volatile char buf[8192];
    for (int i = 0; i < 8192; i += 512) buf[i] = (char)(seed + i);
    int s = 0;
    for (int i = 0; i < 8192; i += 512) s += buf[i];
    return s;
}
KS void ks_out_params(int x, int *q, int *r) {
    *q = x / 7;
    *r = x % 7;
}
