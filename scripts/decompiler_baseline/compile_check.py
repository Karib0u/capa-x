#!/usr/bin/env python3
"""Development-only, crude: how much decompiler text passes a C syntax and type check.

usage: compile_check.py LABEL COMPARISON_JSON      (the file compare.py writes)

Each function is compiled alone with `clang -fsyntax-only -std=gnu89 -w` behind a small typedef
prelude (Ghidra pseudo-types, a few Win32 names), with every undeclared identifier or function
auto-declared (up to six rounds). So a pass means "well-formed C over stubs", not that it links or
behaves like the original. Runs once on native text (n_c) and once on Ghidra's (g_c). The prelude is
tuned to native's type names, so the two columns are not a fair comparison. Compile only; the
output is never run.
"""
import json,re,subprocess,sys,tempfile,os,collections
PRE='''
typedef unsigned char uint1,byte,undefined1,xunknown1,uchar,BYTE; typedef unsigned short uint2,undefined2,xunknown2,ushort,WORD;
typedef unsigned int uint4,undefined4,xunknown4,uint,ulong,DWORD; typedef unsigned long long uint8,undefined8,xunknown8,ulonglong,UINT_PTR;
typedef signed char int1; typedef short int2; typedef int int4; typedef long long int8,longlong; typedef unsigned char bool_; typedef void (*code)();
typedef void *HANDLE,*LPVOID,*LPCVOID,*HMODULE,*HWND,*PVOID,*FARPROC; typedef char *LPSTR,*LPCSTR,*PCHAR; typedef unsigned short *LPWSTR,*LPCWSTR;
typedef unsigned int BOOL,UINT,SIZE_T,ULONG,LONG_PTR; typedef unsigned int *PDWORD,*LPDWORD,*PUINT; typedef unsigned long long uintptr_t_;
#define CARRY4(a,b) 0
#define SBORROW4(a,b) 0
#define SCARRY4(a,b) 0
'''
def check(text):
    stubs=set(); fnstubs=set()
    for _ in range(6):
        src=PRE+''.join(f'extern long long {s};\n' for s in sorted(stubs))+''.join(f'extern long long {s}();\n' for s in sorted(fnstubs))+text
        with tempfile.NamedTemporaryFile('w',suffix='.c',delete=False) as f: f.write(src); p=f.name
        r=subprocess.run(['clang','-fsyntax-only','-std=gnu89','-w','-ferror-limit=0',p],capture_output=True,text=True); os.unlink(p)
        if r.returncode==0: return 'ok', None
        new=False
        for m in re.finditer(r"use of undeclared identifier '(\w+)'",r.stderr):
            n=m.group(1)
            if n not in stubs: stubs.add(n); new=True
        for m in re.finditer(r"call to undeclared function '(\w+)'|implicit declaration of function '(\w+)'",r.stderr):
            n=m.group(1) or m.group(2)
            if n not in fnstubs: fnstubs.add(n); new=True
        if not new: return 'fail', r.stderr
    return 'fail', r.stderr
for label,path,key in ((sys.argv[1],sys.argv[2],'n_c'),(sys.argv[1]+' (Ghidra text)',sys.argv[2],'g_c')):
    rows=[x for x in json.load(open(path)) if x.get(key)]
    c=collections.Counter(); why=collections.Counter()
    for x in rows:
        st,err=check(x[key]); c[st]+=1
        if st=='fail':
            m=re.search(r'error: ([^\n]{0,70})',err or ''); why[re.sub(r"'[^']*'","'X'",m.group(1)) if m else '?']+=1
    print(label,dict(c)); print('   ',why.most_common(6))
