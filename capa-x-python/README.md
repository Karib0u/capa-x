# capa-x-python

In-process Python binding for [capa-x](https://github.com/Karib0u/capa-x):
detect capabilities in PE/ELF/shellcode/.NET/Mach-O programs, called through
the C ABI. No subprocess, no Python at analysis time, nothing reimplemented --
Python calls straight into capa-x's own `capa-x` analysis code.

Distributed as **`capa_x`** wheels, importable as **`capa_x`** --
deliberately neither name Mandiant's own PyPI package (`flare-capa`, imported
as `capa`) uses, so the two are never confused for one another.

## Install

capa-x does not publish to PyPI. Prebuilt `abi3` wheels (one per platform,
covering every CPython >= 3.8) are attached to each
[GitHub release](https://github.com/Karib0u/capa-x/releases); download the
one matching your platform and install it directly:

```bash
pip install capa_x-<version>-cp38-abi3-<platform>.whl
```

Or build from a source checkout with [maturin](https://www.maturin.rs/):

```bash
pip install maturin
cd capa-x-python
maturin develop --release
```

Wheels ship no rules (`capa-rules` is a 4.2 MB, 1,045-file corpus that pinning
it into the wheel would fork on every install); point `Rules.from_directory`
at a checkout, or fetch the pinned release explicitly:

```python
import capa_x

capa_x.fetch_rules("rules")  # clones the pinned capa-rules release
```

## Quickstart: load once, scan many

```python
import capa_x

rules = capa_x.Rules.from_directory("rules")  # parse + validate once

for sample_path in samples:
    try:
        result = capa_x.analyze(sample_path, rules)
    except capa_x.CapaError as e:
        print(f"{sample_path}: {e}")
        continue
    print(sample_path, sorted(result["rules"].keys()))
```

`analyze()` returns upstream capa's own `ResultDocument` schema as a plain
`dict` -- the same shape `capa-x -j` prints, and the same shape
`capa.render.result_document.ResultDocument.model_validate_json` accepts
unmodified, so existing tooling written against Python capa's result
documents keeps working.

`jobs=1` reproduces `capa-x --jobs 1`'s document byte for byte; omit `jobs` to
use all available cores.

## Errors

Every failure raises a typed exception under one `capa_x.CapaError`
base -- a hard error never becomes `None`, an empty result, or a warning:

| Exception | Meaning |
|---|---|
| `InvalidRuleError` | a rule file failed to parse, or the rule set is invalid (raised by `Rules.from_directory`) |
| `UnsupportedFormatError` | the format could not be auto-detected, or an unknown `format=` value |
| `InvalidSignatureError` | a FLIRT signature file failed to parse |
| `CorruptFileError` | the input could not be parsed or analyzed |

## What this is not

A replacement for capa's internal Python API (`capa.features.*`,
`capa.engine`, rule authoring), Python-side extractors or callbacks, or
bindings for any other language. See the main repository's architecture and
contributor documentation for the supported scope.
