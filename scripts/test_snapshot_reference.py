import json
import unittest

from snapshot_reference import prepare_result, sha256


class SnapshotReferenceTests(unittest.TestCase):
    def document(self):
        return {
            "meta": {
                "version": "10.0.0",
                "sample": {"sha256": "sample-hash", "path": "/workspace/sample.exe_"},
                "argv": [
                    "-r", "/workspace/rules", "-s", "/workspace/sigs",
                    "-j", "/workspace/sample.exe_",
                ],
                "analysis": {"rules": ["/workspace/rules"], "layout": {"functions": []}},
            },
            "rules": {
                "example": {
                    "matches": [[{"type": "absolute", "value": 4096}, {"success": True}]],
                    "source": "rule: example",
                }
            },
        }

    def test_preserves_evidence_and_normalizes_invocation_paths(self):
        source = self.document()
        payload, matches = prepare_result(
            json.dumps(source), "sample.exe_", "sample-hash", "10.0.0"
        )
        stored = json.loads(payload)
        self.assertEqual(stored["rules"], source["rules"])
        self.assertEqual(stored["meta"]["analysis"]["layout"], {"functions": []})
        self.assertEqual(stored["meta"]["sample"]["path"], "tests/testfiles/sample.exe_")
        self.assertEqual(stored["meta"]["argv"][3], "reference/capa/sigs")
        self.assertEqual(matches, {"example": [{"type": "absolute", "value": 4096}]})
        self.assertNotIn(b"/workspace", payload)

    def test_rejects_wrong_reference_version(self):
        with self.assertRaisesRegex(ValueError, "reference version"):
            prepare_result(json.dumps(self.document()), "sample.exe_", "sample-hash", "9.4.0")

    def test_sample_aliases_have_distinct_document_keys(self):
        raw = json.dumps(self.document())
        first, first_matches = prepare_result(raw, "first.exe_", "sample-hash", "10.0.0")
        second, second_matches = prepare_result(raw, "second.exe_", "sample-hash", "10.0.0")
        self.assertNotEqual(sha256(first), sha256(second))
        self.assertEqual(first_matches, second_matches)

    def test_rejects_wrong_sample_bytes(self):
        with self.assertRaisesRegex(ValueError, "sample hash"):
            prepare_result(json.dumps(self.document()), "sample.exe_", "different-hash", "10.0.0")


if __name__ == "__main__":
    unittest.main()
