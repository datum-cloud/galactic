"""Regression tests for documentation failures that string matching misses."""

from pathlib import Path
import tempfile
import unittest

from check import api_errors, link_errors, parse_document, resource_names


class MarkdownTests(unittest.TestCase):
    def test_code_and_comments_are_not_links(self):
        document = parse_document('''# Start
`[fake](missing.md)`

```md
[fake](missing.md)
```

    [fake](missing.md)

<!-- [fake](missing.md) -->

[real](exists.md)
''')
        self.assertEqual([link.target for link in document.links], ["exists.md"])

    def test_reference_image_and_html_links(self):
        document = parse_document('''[guide][ref]
![diagram](images/a%20b.svg)
<a href="other.md#here">Other</a>
<img src="images/other.svg" />

[ref]: guide.md#start
''')
        self.assertEqual([link.target for link in document.links],
                         ["guide.md#start", "images/a%20b.svg", "other.md#here", "images/other.svg"])

    def test_heading_anchors_and_aliases(self):
        document = parse_document('''# `Active/active` **egress**
## Café & UDP
## Repeat
## Repeat
## Repeat-1
<a id="old-heading"></a>
<a name="legacy"></a>
''')
        self.assertEqual(document.anchors, {"activeactive-egress", "café--udp", "repeat",
                                          "repeat-1", "repeat-1-1", "old-heading", "legacy"})

    def test_missing_anchors_files_and_outside_paths_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docs = root / "docs"
            docs.mkdir()
            source = docs / "README.md"
            source.write_text("[good](target.md#old)\n[bad](target.md#absent)\n"
                              "[missing](missing.md)\n[outside](../../missing.md)\n")
            (docs / "target.md").write_text('# New\n<a id="old"></a>\n')
            errors = link_errors(root, [source])
            self.assertEqual(len(errors), 3)
            self.assertTrue(any("missing anchor" in error for error in errors))
            self.assertTrue(any("missing file" in error for error in errors))
            self.assertTrue(any("leaves repository" in error for error in errors))

    def test_paths_fragments_and_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docs = root / "docs"
            docs.mkdir()
            (docs / "a b.md").write_text("# Hello\n")
            source = root / "elsewhere.md"
            source.write_text("[good](/docs/a%20b.md#hello)\n[ignored](missing.md)\n"
                              "[bad](docs/a%20b.md#missing)\n[web](https://example.com/absent)\n")
            self.assertEqual(len(link_errors(root, [source])), 1)


class APIReferenceTests(unittest.TestCase):
    def test_real_list_named_resource_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "api/network/v1alpha1"
            package.mkdir(parents=True)
            (package / "types.go").write_text('''package v1alpha1
 type Irrelevant struct {}
type BGPPrefixList struct {
 metav1.ObjectMeta
}
type BGPPrefixListList struct {
 metav1.ListMeta
}
''')
            self.assertEqual(resource_names(package), {"BGPPrefixList"})
            errors = api_errors(root)
            self.assertTrue(any("resource missing from API index: BGPPrefixList" in e for e in errors))

    def test_duplicate_indexes_and_missing_sections_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docs = root / "docs/api"
            docs.mkdir(parents=True)
            package = root / "api/network/v1alpha1"
            package.mkdir(parents=True)
            (package / "types.go").write_text("type Resource struct {\n metav1.ObjectMeta\n}\n")
            for name in ("network-bgp.md", "network-gateway.md"):
                (docs / name).write_text("### Resource Types\n- [Resource](#resource)\n")
            errors = api_errors(root)
            self.assertTrue(any("appears 2 times" in e for e in errors))
            self.assertTrue(any("no section for indexed resource" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
