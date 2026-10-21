#!/bin/sh
# Development-only. usage: run_ghidra_all.sh TESTFILES NAMES_FILE OUT_DIR [JOBS]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$3"
xargs -P "${4:-3}" -n 1 sh -c '"$0/run_ghidra.sh" "$1/$3" "$2/$3.json" 8 || echo "FAILED $3"' "$here" "$1" "$3" < "$2"
