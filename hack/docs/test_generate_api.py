"""Check generated Markdown escaping and the read-only drift gate."""

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from check import parse_document
from generate_api import CONFIG, format_validation_patterns, generate


class GenerationTests(unittest.TestCase):
    def test_array_regex_is_code_not_a_link(self):
        pattern = "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
        raw = "| Validation |\n| --- |\n| items:Pattern: " + pattern + " <br /> |\n"
        rendered = format_validation_patterns(raw)
        self.assertIn("`" + pattern + "`", rendered)
        self.assertEqual(parse_document(rendered).links, [])
        self.assertEqual(format_validation_patterns(rendered), rendered)

    def test_check_detects_drift_without_editing_checkout(self):
        configs = {}

        def render(args, **kwargs):
            flags = dict(arg[2:].split("=", 1) for arg in args if arg.startswith("--") and "=" in arg)
            configs[flags["source-path"]] = yaml.safe_load(Path(flags["config"]).read_text())
            Path(flags["output-path"]).write_text("# API Reference\n\n")

        with tempfile.TemporaryDirectory() as temporary, patch("generate_api.subprocess.run", side_effect=render):
            root = Path(temporary)
            (root / CONFIG).write_text(
                "render: {markdown: {mediaWidth: 80}}\n"
                "references:\n"
                "  - {name: one, source: api/one, processor: {ignoreTypes: [OneList]}}\n"
                "  - {name: two, source: api/two, processor: {ignoreTypes: [TwoList]}}\n"
            )
            self.assertTrue(generate(root, check=False))
            render_settings = {"markdown": {"mediaWidth": 80}}
            self.assertEqual(configs, {
                "api/one": {"processor": {"ignoreTypes": ["OneList"]}, "render": render_settings},
                "api/two": {"processor": {"ignoreTypes": ["TwoList"]}, "render": render_settings},
            })
            self.assertTrue(generate(root, check=True))
            target = root / "docs/api/one.md"
            target.write_text("# Stale reference\n")
            before = {path: path.read_bytes() for path in (root / "docs/api").glob("*.md")}
            with redirect_stdout(StringIO()):
                self.assertFalse(generate(root, check=True))
            self.assertEqual(before, {path: path.read_bytes() for path in before})


if __name__ == "__main__":
    unittest.main()
