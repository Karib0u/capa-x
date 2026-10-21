/* Compile with scripts/build_decompiler_fixtures.sh. Windows x64 ABI. */
__declspec(dllimport) unsigned long __stdcall GetTickCount(void);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned int);
#define EXPORT __declspec(dllexport) __attribute__((noinline))
EXPORT int arithmetic(int x, int y) { return x * 7 + y - 3; }
EXPORT int branches(int x) { if (x < 0) return -x; if (x > 100) return 100; return x + 1; }
EXPORT int loops(int n) { int sum = 0; for (int i = 0; i < n; ++i) sum += i * i; return sum; }
EXPORT int switches(int x, int y) {
    switch (x) {
    case 0: return arithmetic(y, 13);
    case 1: return branches(y);
    case 2: return loops(y);
    case 3: return arithmetic(y, 27);
    case 4: return arithmetic(y, 91);
    case 5: return branches(y + 12);
    case 6: return loops(y + 2);
    default: return -1;
    }
}
EXPORT int stack_variables(int x) { volatile int a[4]; a[0] = x; a[1] = x + 9; return a[x & 1]; }
EXPORT unsigned long imported_call(unsigned long x) { return GetTickCount() + x; }
EXPORT void nonreturn(unsigned int code) { ExitProcess(code); }
