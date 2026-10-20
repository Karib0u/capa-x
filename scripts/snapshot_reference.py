#!/usr/bin/env python3
"""Archive pinned capa results for a corpus, with explicit failure records.

Run difftest.py first to populate its reference cache. This command never
substitutes capa-x output for a missing reference result. Only invocation
paths are made repository-relative; matching evidence is preserved.
"""

import argparse
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def prepare_result(raw, sample, digest, version):
    doc = json.loads(raw)
    meta = doc["meta"]
    if meta["version"] != version:
        raise ValueError(f"{sample}: reference version is {meta['version']}, expected {version}")
    if meta["sample"]["sha256"] != digest:
        raise ValueError(f"{sample}: reference sample hash does not match input bytes")
    replacements = {meta["sample"]["path"]: f"tests/testfiles/{sample}"}
    for path in meta["analysis"]["rules"]:
        replacements[path] = "rules"
    argv = meta.get("argv") or []
    for index, arg in enumerate(argv[:-1]):
        if arg in ("-s", "--signatures"):
            replacements[argv[index + 1]] = "reference/capa/sigs"
    meta["argv"] = [replacements.get(arg, arg) for arg in argv]
    meta["sample"]["path"] = f"tests/testfiles/{sample}"
    meta["analysis"]["rules"] = ["rules"]
    matches = {
        name: [match[0] for match in rule["matches"]]
        for name, rule in sorted(doc["rules"].items())
    }
    return encode(doc), matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, default=ROOT / "scripts/corpus-full-static.txt")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / ".cache/difftest")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failures", type=Path, help="JSON object: sample path to reference error")
    args = parser.parse_args()
    pin_text = (ROOT / "PINNED.md").read_text()
    version_match = re.search(r"\| `flare-capa`.*?\| `([^`]+)`", pin_text)
    if version_match is None:
        raise ValueError("PINNED.md has no flare-capa version")
    version = version_match.group(1)
    pins = {
        path: subprocess.check_output(
            ["git", "-C", str(ROOT / path), "rev-parse", "HEAD"], text=True
        ).strip()
        for path in ("reference/capa", "rules", "tests/testfiles")
    }
    environment = json.loads(subprocess.check_output(
        [
            str(ROOT / ".venv/bin/python3"), "-c",
            "import json,sys; from importlib.metadata import version; "
            "print(json.dumps({'python':sys.version.split()[0], **{name:version(name) "
            "for name in ['flare-capa','vivisect','viv-utils','python-flirt','pefile']}}))",
        ],
        text=True,
    ))
    if environment["flare-capa"] != version:
        raise ValueError("installed reference does not match PINNED.md")
    failures = json.loads(args.failures.read_text()) if args.failures else {}
    samples = [
        line.strip() for line in args.samples.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(samples) != len(set(samples)):
        raise ValueError("corpus contains duplicate paths")
    if set(failures) - set(samples):
        raise ValueError("failure records include samples outside the corpus")
    entries = []
    results = {}
    matches = {}
    for sample in samples:
        digest = sha256((ROOT / "tests/testfiles" / sample).read_bytes())
        entry = {"sample": sample, "sha256": digest}
        cached = args.cache_dir / f"{digest}.full.json"
        if not cached.exists():
            if not isinstance(failures.get(sample), str) or not failures[sample].strip():
                raise ValueError(f"{sample}: missing reference result and explicit failure record")
            entry.update(status="reference-error", error=failures[sample])
        else:
            if sample in failures:
                raise ValueError(f"{sample}: both a reference result and failure record exist")
            raw = cached.read_bytes()
            payload, sample_matches = prepare_result(raw, sample, digest, version)
            # Identical sample bytes can have several corpus filenames.
            # Key by the normalized document, so their distinct invocation
            # metadata cannot overwrite each other's archive/checksum.
            relative = f"results/{sha256(payload)}.json.gz"
            compressed = gzip.compress(payload, mtime=0)
            results[relative] = compressed
            matches[sample] = sample_matches
            entry.update(
                status="ok",
                result=relative,
                result_sha256=sha256(compressed),
                original_json_sha256=sha256(raw),
                matched_rules=len(sample_matches),
            )
        entries.append(entry)
    # Validate every input before publishing a manifest. Re-running with the
    # same cache produces the same archive bytes.
    args.output.mkdir(parents=True, exist_ok=True)
    for relative, compressed in results.items():
        path = args.output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(compressed)
    index = gzip.compress(encode(matches), mtime=0)
    (args.output / "matches.json.gz").write_bytes(index)
    manifest = {
        "schema_version": 1,
        "reference_version": version,
        "validation_environment": environment,
        "pins": pins,
        "corpus_sha256": sha256(args.samples.read_bytes()),
        "metadata_normalization": "Only sample, rules, and signature invocation paths are repository-relative.",
        "matches_index": {"path": "matches.json.gz", "sha256": sha256(index)},
        "samples": entries,
    }
    (args.output / "manifest.json").write_bytes(encode(manifest))
    print(
        f"Saved {len(entries) - len(failures)} successful sample records "
        f"({len(results)} unique documents) and {len(failures)} reference failures to {args.output}"
    )


if __name__ == "__main__":
    main()
