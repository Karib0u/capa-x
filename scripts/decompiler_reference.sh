#!/bin/sh
set -eu
: "${GHIDRA_HOME:?Set GHIDRA_HOME to Ghidra 11.4.2 PUBLIC}"
cd "$(dirname "$0")/.."
workspace=$(pwd)
project=$(mktemp -d)
trap 'rm -rf "$project"' EXIT
"$GHIDRA_HOME/support/analyzeHeadless" "$project" fixtures \
  -import "$workspace/tests/decompiler/fixtures.dll" \
  -scriptPath "$workspace/scripts/ghidra" \
  -postScript ExportDecompilerFixtures.java "$workspace/tests/decompiler/reference" \
  -deleteProject

# Headless Ghidra can exit successfully even when a post-script fails.
for function in arithmetic branches loops switches stack_variables imported_call nonreturn; do
  test -s "$workspace/tests/decompiler/reference/$function.c"
done
