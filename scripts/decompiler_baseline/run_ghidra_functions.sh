#!/bin/sh
# Development-only. usage: run_ghidra_functions.sh SAMPLE_PATH OUT_JSON
set -eu
: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra install}"
here=$(cd "$(dirname "$0")" && pwd)
project=$(mktemp -d)
trap 'rm -rf "$project"' EXIT
"$GHIDRA_HOME/support/analyzeHeadless" "$project" p -import "$1" \
  -analysisTimeoutPerFile 900 -scriptPath "$here" \
  -postScript FunctionList.java "$2" -deleteProject > "$2.log" 2>&1 || true
test -s "$2"
