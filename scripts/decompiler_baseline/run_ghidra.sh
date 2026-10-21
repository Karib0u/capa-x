#!/bin/sh
# Development-only. usage: run_ghidra.sh SAMPLE_PATH OUT_JSON [FUNCTIONS_PER_SAMPLE]
set -eu
: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra install}"
here=$(cd "$(dirname "$0")" && pwd)
project=$(mktemp -d)
trap 'rm -rf "$project"' EXIT
"$GHIDRA_HOME/support/analyzeHeadless" "$project" p -import "$1" \
  -analysisTimeoutPerFile 900 -scriptPath "$here" \
  -postScript BaselineExport.java "$2" "${3:-8}" -deleteProject > "$2.log" 2>&1 || true
test -s "$2"
