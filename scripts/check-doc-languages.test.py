#!/usr/bin/env python3
"""Failing-side checks for the bilingual publication gate."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("doc_languages", Path(__file__).with_name("check-doc-languages.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class LanguageGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        self.de = "# Anleitung\n\nSprachen / Languages: [Deutsch](guide.de.md) | [English](guide.md)\n\n```sh\nskillctl help\n```\n"
        self.en = self.de.replace("Anleitung", "Guide")
        self.write_pair()

    def write_pair(self):
        (self.root / "docs/guide.de.md").write_text(self.de)
        (self.root / "docs/guide.md").write_text(self.en)
        self.manifest = self.root / "docs/languages.json"
        self.manifest.write_text(json.dumps({"pairs": [{
            "de": "docs/guide.de.md", "en": "docs/guide.md",
            "de_sha256": hashlib.sha256(self.de.encode()).hexdigest(),
            "en_sha256": hashlib.sha256(self.en.encode()).hexdigest(),
        }]}))

    def test_complete_pair(self):
        self.assertEqual(gate.check(self.root, self.manifest), [])

    def test_indented_code_is_checked(self):
        self.de = self.de.replace("```sh", "  ```sh").replace("\n```", "\n  ```").replace("skillctl help", "skillctl revoke dangerous")
        self.en = self.en.replace("```sh", "  ```sh").replace("\n```", "\n  ```")
        self.write_pair()
        self.assertTrue(any("examples differ" in e for e in gate.check(self.root, self.manifest)))

    def test_quoted_code_is_checked(self):
        self.de = self.de.replace("```sh", "> ```sh").replace("\n```", "\n> ```").replace("skillctl help", "> skillctl revoke dangerous")
        self.en = self.en.replace("```sh", "> ```sh").replace("\n```", "\n> ```").replace("skillctl help", "> skillctl help")
        self.write_pair()
        self.assertTrue(any("examples differ" in e for e in gate.check(self.root, self.manifest)))

    def test_switch_hidden_in_example_is_rejected(self):
        self.de = self.de.replace("[Deutsch](guide.de.md) | [English](guide.md)", "") + "\n```text\nSprachen / Languages: [Deutsch](guide.de.md) | [English](guide.md)\n```\n"
        self.write_pair()
        self.assertTrue(any("missing language link" in e for e in gate.check(self.root, self.manifest)))

    def test_root_document_is_inventoried(self):
        (self.root / "README.md").write_text("# New publication\n")
        self.assertTrue(any("README.md: published" in e for e in gate.check(self.root, self.manifest)))

    def test_uppercase_extension_is_inventoried(self):
        (self.root / "docs/EXTRA.MD").write_text("# New publication\n")
        self.assertTrue(any("EXTRA.MD: published" in e for e in gate.check(self.root, self.manifest)))

    def test_switch_hidden_in_inline_code_is_rejected(self):
        self.de = self.de.replace("Sprachen / Languages: [Deutsch](guide.de.md) | [English](guide.md)", "`Sprachen / Languages: [Deutsch](guide.de.md) | [English](guide.md)`")
        self.write_pair()
        self.assertTrue(any("missing language link" in e for e in gate.check(self.root, self.manifest)))

    def test_combined_list_and_quote_code_is_checked(self):
        self.de = self.de.replace("```sh", "- > ```sh").replace("\n```", "\n  > ```").replace("skillctl help", "  > skillctl revoke dangerous")
        self.en = self.en.replace("```sh", "- > ```sh").replace("\n```", "\n  > ```").replace("skillctl help", "  > skillctl help")
        self.write_pair()
        self.assertTrue(any("examples differ" in e for e in gate.check(self.root, self.manifest)))

    def test_tool_cache_is_not_a_published_document(self):
        cache = self.root / "rag-mcp-server/.pytest_cache"
        cache.mkdir(parents=True)
        (cache / "README.md").write_text("# pytest cache directory\n")
        self.assertEqual(gate.check(self.root, self.manifest), [])

    def test_missing_section(self):
        self.en += "\n## Additional section\n"
        self.write_pair()
        self.assertTrue(any("heading structure" in e for e in gate.check(self.root, self.manifest)))

    def test_missing_translation(self):
        (self.root / "docs/guide.de.md").unlink()
        self.assertTrue(any("missing DE" in e for e in gate.check(self.root, self.manifest)))

    def test_unreviewed_source_change(self):
        (self.root / "docs/guide.md").write_text(self.en + "New instruction.\n")
        self.assertTrue(any("changed since" in e for e in gate.check(self.root, self.manifest)))

    def test_different_command(self):
        self.de = self.de.replace("skillctl help", "skillctl version")
        self.write_pair()
        self.assertTrue(any("examples differ" in e for e in gate.check(self.root, self.manifest)))

    def test_unregistered_document(self):
        (self.root / "docs/hidden.md").write_text("# More\n")
        self.assertTrue(any("no registered" in e for e in gate.check(self.root, self.manifest)))

    def test_missing_switch(self):
        self.de = self.de.replace("[English](guide.md)", "English")
        self.write_pair()
        self.assertTrue(any("missing language link" in e for e in gate.check(self.root, self.manifest)))

    def test_english_copy_is_not_translation(self):
        self.de = self.en
        self.write_pair()
        self.assertTrue(any("real translation" in e for e in gate.check(self.root, self.manifest)))


if __name__ == "__main__":
    unittest.main()
