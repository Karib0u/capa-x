#include <windows.h>
#include <stdlib.h>
#include "ks.h"

KS int ks_message(const char *text) {
    return MessageBoxA(NULL, text, "ks", MB_OK | MB_ICONINFORMATION);
}
KS void *ks_resolve(const char *dll, const char *fn) {
    HMODULE m = LoadLibraryA(dll);
    if (!m) return NULL;
    return (void *)GetProcAddress(m, fn);
}
KS unsigned ks_tick_delta(void) {
    DWORD a = GetTickCount();
    Sleep(10);
    return GetTickCount() - a;
}
KS int ks_write_file(const char *path, const void *buf, unsigned len) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD written = 0;
    BOOL ok = WriteFile(h, buf, len, &written, NULL);
    CloseHandle(h);
    return ok ? (int)written : -2;
}
KS void ks_die(const char *why) {
    OutputDebugStringA(why);
    ExitProcess(3);
}
