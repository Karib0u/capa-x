/* Trivial fixture source for capa-x's AArch64 PE corpus (V3-0 task 4,
 * docs/development/milestones/v3/V3-0-oracles-and-seam.md). No Windows SDK
 * is available in this build environment, so this is `-nostdlib` with its
 * own entry point rather than a real `main`/CRT-started program -- it
 * links and produces a genuine, loadable ARM64 PE, but is not meant to run
 * under Windows (there is no OS to run it under here to check). What
 * matters for the fixture is real compiler+linker output: real ARM64
 * machine code, a real import thunk resolved through `fake.lib` (built
 * from fake.def -- see build.sh), and the `.pdata`/exception-directory
 * unwind info the ARM64 Windows ABI requires the linker to emit for every
 * function. */
__declspec(dllimport) int FakeImportedFunc(int x);

static int add(int a, int b) {
    return a + b;
}

static int mul(int a, int b) {
    return a * b;
}

void entry_point(void) {
    int x = add(2, 3);
    int y = mul(x, 4);
    FakeImportedFunc(y);
}
