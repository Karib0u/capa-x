"""python3 -I show.py BUILD FUNCTION: print the native text and issues from out/report.json."""
import json, sys
for row in json.load(open("out/report.json"))["rows"]:
    if row["build"] == sys.argv[1] and row["function"] == sys.argv[2]:
        print(row.get("source"), "\n", row.get("native"), "\n", row["issues"], row.get("warnings"))
        print(row.get("text"))
        print("--- Ghidra:", row.get("ghidra_native"), row.get("ghidra_issues"))
        print(row.get("ghidra_text"))
