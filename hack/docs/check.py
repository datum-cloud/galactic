#!/usr/bin/env python3
"""Check local documentation links, GitHub anchors and generated API coverage."""

import argparse
from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import unicodedata
from urllib.parse import unquote, urlsplit

from markdown_it import MarkdownIt


ROOT = Path(__file__).resolve().parents[2]
MARKDOWN = MarkdownIt("commonmark").enable("table")
API_PACKAGES = {
    "api/v1alpha1": ("galactic.md",),
    "api/cloud/v1alpha1": ("cloud.md",),
    "api/network/v1alpha1": ("network-bgp.md", "network-gateway.md"),
}


@dataclass(frozen=True)
class Link:
    target: str
    line: int


@dataclass
class Document:
    anchors: set[str]
    links: list[Link]


class HTMLLinks(HTMLParser):
    """Collect explicit anchors and local destinations without inspecting comments."""

    def __init__(self, line: int):
        super().__init__(convert_charrefs=True)
        self.line = line
        self.anchors: set[str] = set()
        self.links: list[Link] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.anchors.add(attrs["id"])
        if tag == "a" and attrs.get("name"):
            self.anchors.add(attrs["name"])
        attribute = "href" if tag == "a" else "src" if tag == "img" else None
        if attribute and attrs.get(attribute):
            self.links.append(Link(attrs[attribute], self.line + self.getpos()[0] - 1))

    handle_startendtag = handle_starttag


def heading_text(tokens) -> str:
    """Extract visible text, including code and image labels, from a heading."""
    return "".join(
        token.content if token.type in ("text", "code_inline")
        else heading_text(token.children or []) if token.type == "image"
        else " " if token.type in ("softbreak", "hardbreak") else ""
        for token in tokens
    )


def slug(text: str) -> str:
    """Apply GitHub's heading punctuation removal and space replacement."""
    return "".join(
        char for char in text.lower()
        if char in "-_ " or unicodedata.category(char)[0] in "LNM"
    ).replace(" ", "-")


def parse_document(text: str) -> Document:
    tokens = MARKDOWN.parse(text)
    document = Document(set(), [])
    generated: set[str] = set()
    heading = False
    for token in tokens:
        if token.type == "heading_open":
            heading = True
        elif token.type == "heading_close":
            heading = False
        elif token.type == "inline":
            line = token.map[0] + 1 if token.map else 1
            if heading:
                base = slug(heading_text(token.children or []))
                anchor = base
                suffix = 0
                while anchor in generated:
                    suffix += 1
                    anchor = f"{base}-{suffix}"
                generated.add(anchor)
                document.anchors.add(anchor)
            for child in token.children or []:
                if child.type == "link_open":
                    document.links.append(Link(child.attrGet("href"), line))
                elif child.type == "image":
                    document.links.append(Link(child.attrGet("src"), line))
                elif child.type == "html_inline":
                    html = HTMLLinks(line)
                    html.feed(child.content)
                    document.anchors.update(html.anchors)
                    document.links.extend(html.links)
                elif child.type in ("softbreak", "hardbreak"):
                    line += 1
        elif token.type == "html_block":
            html = HTMLLinks(token.map[0] + 1 if token.map else 1)
            html.feed(token.content)
            document.anchors.update(html.anchors)
            document.links.extend(html.links)
    return document


def link_errors(root: Path, sources: list[Path]) -> list[str]:
    """Check all links in docs/ and entry points, and links into docs/ elsewhere."""
    root = root.resolve()
    documents = {}
    errors = []

    def read(path):
        if path not in documents:
            documents[path] = parse_document(path.read_text())
        return documents[path]

    for source in sources:
        source = source.resolve()
        relative = source.relative_to(root)
        complete = relative.parts[0] == "docs" or str(relative) in ("README.md", "AGENTS.md")
        for link in read(source).links:
            url = urlsplit(link.target)
            if url.scheme or url.netloc:
                continue
            path = unquote(url.path)
            target = (root / path.lstrip("/") if path.startswith("/")
                      else source.parent / path if path else source).resolve()
            if not complete and not target.is_relative_to(root / "docs"):
                continue
            location = f"{relative}:{link.line}"
            if not target.is_relative_to(root):
                errors.append(f"{location}: link leaves repository: {link.target}")
                continue
            if not target.exists():
                errors.append(f"{location}: missing file: {link.target}")
                continue
            if target.is_dir():
                target = target / "README.md"
                if not target.exists():
                    if url.fragment:
                        errors.append(f"{location}: directory has no README for anchor: {link.target}")
                    continue
            if target.suffix.lower() == ".md" and url.fragment:
                anchor = unquote(url.fragment)
                if anchor not in read(target).anchors:
                    errors.append(f"{location}: missing anchor: {link.target}")
    return errors


def resource_names(package: Path) -> set[str]:
    """Find resource structs by ObjectMeta, not by suffix (PrefixList is a kind)."""
    names = set()
    for source in package.glob("*.go"):
        if source.name.endswith("_test.go"):
            continue
        for match in re.finditer(r"^type (\w+) struct \{(.*?)^\}", source.read_text(), re.M | re.S):
            if re.search(r"\bmetav1\.ObjectMeta\b", match[2]):
                names.add(match[1])
    return names


def indexed_resources(text: str) -> list[str]:
    match = re.search(r"^### Resource Types\s*\n(.*?)(?=^#{1,4} |\Z)", text, re.M | re.S)
    return re.findall(r"^- \[([^]]+)\]\(#[^)]+\)", match[1], re.M) if match else []


def api_errors(root: Path) -> list[str]:
    errors = []
    for package, references in API_PACKAGES.items():
        indexed = Counter()
        for name in references:
            path = root / "docs/api" / name
            if not path.exists():
                errors.append(f"docs/api/{name}: missing generated reference")
                continue
            text = path.read_text()
            resources = indexed_resources(text)
            indexed.update(resources)
            anchors = parse_document(text).anchors
            for resource in resources:
                if slug(resource) not in anchors:
                    errors.append(f"docs/api/{name}: no section for indexed resource {resource}")
        expected = resource_names(root / package)
        for missing in sorted(expected - indexed.keys()):
            errors.append(f"{package}: resource missing from API index: {missing}")
        for extra in sorted(indexed.keys() - expected):
            errors.append(f"{package}: index names an unknown resource: {extra}")
        for name, count in sorted(indexed.items()):
            if count != 1:
                errors.append(f"{package}: resource appears {count} times in API indexes: {name}")
    return errors


def markdown_sources(root: Path) -> list[Path]:
    """Include uncommitted docs and tracked Markdown callers without walking worktrees."""
    result = subprocess.run(["git", "ls-files", "-z", "--", "*.md"], cwd=root,
                            check=True, capture_output=True, text=True)
    sources = {root / name for name in result.stdout.split("\0") if name}
    sources.update((root / "docs").rglob("*.md"))
    return sorted({p.resolve() for p in sources if p.is_file()})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root")
    args = parser.parse_args()
    root = args.root.resolve()
    sources = markdown_sources(root)
    errors = link_errors(root, sources) + api_errors(root)
    if errors:
        print("\n".join(errors))
        print(f"Documentation check failed: {len(errors)} errors.")
        return 1
    print(f"Documentation links and API resource coverage passed ({len(sources)} Markdown files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
