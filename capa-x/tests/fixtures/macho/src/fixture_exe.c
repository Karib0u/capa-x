/* Trivial fixture source for capa-x's Mach-O corpus (V3-0 task 4,
 * docs/development/milestones/v3/V3-0-oracles-and-seam.md). Calls a real
 * libSystem import (puts) and allocates/frees via malloc/free so the built
 * binary has ordinary lazy-bound stubs to resolve, plus one internal
 * function so the fixture isn't trivially just an import thunk. The large
 * uninitialized static array gives the linker a __DATA.__bss zero-fill
 * section (S_ZEROFILL): no file bytes back it, only vmsize -- exactly the
 * `filesize`-vs-`vmsize` split a loader must map correctly (distinct from,
 * and a legitimate case of, the deliberately-malformed
 * `filesize-gt-vmsize` fixture in malformed/). */
#include <stdio.h>
#include <stdlib.h>

static int add(int a, int b) {
    return a + b;
}

static int zero_fill_buffer[4096];

int main(int argc, char **argv) {
    (void)argv;
    int sum = add(argc, 41);
    zero_fill_buffer[argc % 4096] = sum;
    void *buf = malloc(16);
    if (buf != NULL) {
        puts("capa-x macho fixture");
        free(buf);
    }
    return sum == 42 && zero_fill_buffer[0] == 0 ? 0 : 1;
}
