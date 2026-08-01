# AArch64 PE fixture corpus

Built for AArch64-PE acceptance and used as the structural oracle. Not part of
the read-only
`tests/testfiles/` submodule.

## Why these are hand-linked rather than a normal compiler test binary

No Windows SDK is available in this build environment, so there is no
`kernel32.lib`/CRT to link a normal, runnable `main()`-based Windows binary
against. These fixtures are `-nostdlib` with a custom entry point instead —
see each `src/*.c` file's own comment — which means they are **not meant to
run under Windows** (there is no Windows here to check that on anyway).
What matters for a loader/parser fixture is that the bytes are genuine
compiler-and-linker output: real ARM64 machine code, a real resolved
import (against a stub import library built from a `.def` file, not a real
DLL), real exports, and the `.pdata`/exception-directory unwind info the
ARM64 Windows ABI requires the linker to emit for every function — all
confirmed present and non-empty in both fixtures below via `llvm-readobj`.

## Toolchain

Unlike the Mach-O corpus, this needs tooling beyond a bare macOS dev
machine:

- **Compiler**: Homebrew's LLVM (`brew install llvm`; `clang --target=
  aarch64-pc-windows-msvc` emits ARM64 COFF directly — Apple's system
  clang cannot target Windows).
- **Linker**: Homebrew's `lld` (`brew install lld`) for `lld-link` — not
  bundled in the `llvm` bottle itself.
- Both were already installed, or installed fresh, when this corpus was
  built; see [`build.sh`](build.sh) for the exact invocation.
- **Source**: `src/fixture_exe.c`, `src/fixture_dll.c`, `src/fake.def` —
  original, trivial code written for this repository (public-domain/CC0-
  equivalent, same as the Mach-O corpus's sources).
- **Rebuilding**: `./build.sh` from this directory.

## Fixtures

| File | sha256 | Description |
|---|---|---|
| `exe-with-import.exe` | `9319db22...5c83dc1` | ARM64 PE executable; one resolved import (`FakeImportedFunc`, via a stub import library built from `fake.def`), `.pdata`/exception directory populated (`ExceptionTableRVA`/`Size` non-zero) |
| `dll-with-export.dll` | `c64bf560...9eb4ec8` | ARM64 PE DLL; two exports (`ExportedAdd`, `ExportedMul`), `.pdata`/exception directory populated |

Each has a captured `<name>.oracle.json` (`llvm-readobj --all` plus
`--coff-exports` output, wrapped in a small JSON envelope — see
[`capture_oracles.py`](capture_oracles.py)), generated at build time and
never invoked at test time.

There is no malformed AArch64-PE set. This corpus covers imports, exports,
`.pdata`, and exception-function entries. A malformed-PE corpus is general
PE-loader hardening, not AArch64-specific, and belongs with the existing PE
loader tests rather than here.
