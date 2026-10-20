"""Regression checks for result-document comparison, using only the stdlib."""

import copy
import unittest

from difftest import diff_value, normalize_match_evidence, normalize_result_doc


def feature(name, addresses):
    return {
        "node": {"type": "feature", "feature": {"type": "api", "api": name}},
        "success": True,
        "children": [],
        "locations": [{"type": "absolute", "value": address} for address in addresses],
        "captures": {},
    }


def statement(kind, children):
    return {
        "node": {"type": "statement", "statement": {"type": kind}},
        "success": True,
        "children": children,
        "locations": [],
        "captures": {},
    }


class EvidenceComparisonTests(unittest.TestCase):
    def differences(self, left, right):
        problems = []
        diff_value(normalize_match_evidence(left), normalize_match_evidence(right), "$", problems)
        return problems

    def test_spliced_children_and_their_location_sets_are_unordered(self):
        left = statement("subscope", [feature("read", [1, 2]), feature("write", [3])])
        right = statement("subscope", [feature("write", [3]), feature("read", [2, 1])])
        self.assertEqual(self.differences(left, right), [])

    def test_nested_namespace_evidence_is_unordered(self):
        left = statement("subscope", [feature("read", [1]), feature("write", [2])])
        left["node"] = {"type": "feature", "feature": {"type": "match", "match": "namespace"}}
        right = copy.deepcopy(left)
        right["children"].reverse()
        self.assertEqual(
            self.differences(statement("and", [left]), statement("and", [right])), []
        )

    def test_statement_order_stays_significant(self):
        for kind in ("and", "or", "some"):
            with self.subTest(kind=kind):
                left = statement(kind, [feature("read", [1]), feature("write", [2])])
                right = copy.deepcopy(left)
                right["children"].reverse()
                self.assertTrue(self.differences(left, right))

    def test_determinism_normalization_preserves_evidence_order(self):
        evidence = statement("subscope", [feature("write", [2, 1]), feature("read", [3])])
        doc = {"rules": {"rule": {"matches": [[{}, evidence]]}}}
        original = copy.deepcopy(doc)
        normalize_result_doc(doc, normalize_evidence=False)
        self.assertEqual(doc, original)

    def test_missing_evidence_and_duplicate_children_are_detected(self):
        left = statement("subscope", [feature("read", [1, 2])])
        self.assertTrue(self.differences(left, statement("subscope", [feature("read", [1])])))
        right = copy.deepcopy(left)
        right["children"] *= 2
        self.assertTrue(self.differences(left, right))

    def test_only_synthetic_suffixes_and_capture_order_are_ignored(self):
        left = feature("read", [1])
        left["node"]["feature"] = {"type": "match", "match": "parent/" + "a" * 32}
        left["captures"] = {
            "text": [{"type": "absolute", "value": 1}, {"type": "absolute", "value": 2}]
        }
        right = copy.deepcopy(left)
        right["node"]["feature"]["match"] = "parent/0"
        right["captures"]["text"].reverse()
        self.assertEqual(self.differences(left, right), [])
        right["node"]["feature"]["match"] = "different/0"
        self.assertTrue(self.differences(left, right))


if __name__ == "__main__":
    unittest.main()
