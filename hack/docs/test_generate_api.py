"""Check generated Markdown escaping and the read-only drift gate."""

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check import parse_document
from generate_api import format_validation_patterns, generate, REFERENCES


class GenerationTests(unittest.TestCase):
    def test_array_regex_is_code_not_a_link(self):
        pattern = "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
        raw = "| Validation |\n| --- |\n| items:Pattern: " + pattern + " <br /> |\n"
        rendered = format_validation_patterns(raw)
        self.assertIn("`" + pattern + "`", rendered)
        self.assertEqual(parse_document(rendered).links, [])
        self.assertEqual(format_validation_patterns(rendered), rendered)

    def test_check_detects_drift_without_editing_checkout(self):
        def render(args, **kwargs):
            output = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output-path="))
            Path(output).write_text("# API Reference\n\n")

        with tempfile.TemporaryDirectory() as temporary, patch("generate_api.subprocess.run", side_effect=render):
            root = Path(temporary)
            self.assertTrue(generate(root, check=False))
            self.assertTrue(generate(root, check=True))
            target = root / "docs/api" / f"{REFERENCES[0][1]}.md"
            target.write_text("# Stale reference\n")
            before = {path: path.read_bytes() for path in (root / "docs/api").glob("*.md")}
            with redirect_stdout(StringIO()):
                self.assertFalse(generate(root, check=True))
            self.assertEqual(before, {path: path.read_bytes() for path in before})


if __name__ == "__main__":
    unittest.main()
