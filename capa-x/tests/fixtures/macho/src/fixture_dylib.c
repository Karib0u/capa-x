/* Trivial fixture source for capa-x's Mach-O corpus (V3-0 task 4,
 * docs/development/milestones/v3/V3-0-oracles-and-seam.md). Exports two
 * ordinary symbols and calls a libSystem import (memset) internally, so the
 * built dylib has both exports and an import stub to resolve. */
#include <string.h>

int capa_fixture_add(int a, int b) {
    return a + b;
}

int capa_fixture_zero_and_sum(int *buf, int count) {
    memset(buf, 0, (unsigned long)count * sizeof(int));
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += buf[i];
    }
    return sum;
}
