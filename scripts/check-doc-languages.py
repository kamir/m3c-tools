#!/usr/bin/env python3
"""Check published DE/EN documentation pairs and reviewed content digests."""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path


def markdown_parts(text):
    """Recognize fenced examples inside indentation, lists and block quotes."""
    examples, prose, body = [], [], []
    fence = None
    for line in text.splitlines(keepends=True):
        content = line
        while True:
            reduced = re.sub(r"^[ \t]*(?:>[ \t]*|(?:[-+*]|[0-9]+[.)])[ \t]+)", "", content, count=1)
            if reduced == content:
                break
            content = reduced
        match = re.match(r"^[ \t]*(`{3,}|~{3,})([^\n]*)", content)
        if fence is None:
            if match:
                fence = (match[1][0], len(match[1]), match[2].strip())
                body = []
            else:
                prose.append(line)
        elif match and match[1][0] == fence[0] and len(match[1]) >= fence[1] and not match[2].strip():
            examples.append((fence[2], "".join(body)))
            fence = None
        else:
            body.append(line)
    if fence is not None:
        examples.append(("unclosed:" + fence[2], "".join(body)))
    return examples, re.sub(r"<!--[\s\S]*?-->", "", "".join(prose))


def blocks(text):
    return markdown_parts(text)[0]


def headings(text):
    return re.findall(r"(?m)^(#{1,6})[ \t]+", markdown_parts(text)[1])


def published_paths(root):
    paths = {p for p in (root / "docs").rglob("*") if p.is_file() and p.suffix.lower() == ".md"}
    paths.update(p for p in root.iterdir() if p.is_file() and p.suffix.lower() == ".md" and p.name.upper() not in {"CLAUDE.MD", "AGENTS.MD", "CHANGELOG.MD"})
    for directory in ("demo", "deploy", "design", "evaluation", "rag-mcp-server", "tools", "tests/evidence"):
        for path in (root / directory).rglob("*"):
            relative = path.relative_to(root).parts
            if any(part.startswith(".") for part in relative):
                continue
            if path.is_file() and path.suffix.lower() == ".md" and "fixtures" not in path.parts and "testdata" not in path.parts:
                if path.name.upper().startswith(("README", "TUTORIAL", "DESIGN-SYSTEM")):
                    paths.add(path)
    return sorted(paths)


def check(root, manifest):
    errors = []
    data = json.loads(manifest.read_text(encoding="utf-8"))
    registered = set()
    for pair in data["pairs"]:
        contents = {}
        for language in ("de", "en"):
            name = pair[language]
            if name in registered:
                errors.append(f"{name}: registered more than once")
            registered.add(name)
            path = root / name
            if not path.is_file():
                errors.append(f"{name}: missing {language.upper()} document")
                continue
            payload = path.read_bytes()
            contents[language] = payload.decode("utf-8")
            if hashlib.sha256(payload).hexdigest() != pair[f"{language}_sha256"]:
                errors.append(f"{name}: changed since bilingual review; review both versions and update digests")
            for target in (pair["de"], pair["en"]):
                relative = Path(os.path.relpath(root / target, path.parent)).as_posix()
                navigation = markdown_parts(contents[language])[1]
                switches = [line for line in navigation.splitlines() if re.fullmatch(r"(?:Sprachen / Languages:[ \t]*)?\[Deutsch\]\([^)]*\)[ \t]*[|·][ \t]*\[English\]\([^)]*\)[ \t]*", line.strip())]
                if not any(f"]({relative})" in line for line in switches):
                    errors.append(f"{name}: missing language link to {relative}")
        if len(contents) == 2:
            if blocks(contents["de"]) != blocks(contents["en"]):
                errors.append(f"{pair['de']}: fenced examples differ from English version")
            if headings(contents["de"]) != headings(contents["en"]):
                errors.append(f"{pair['de']}: heading structure differs from English version")
            if contents["de"] == contents["en"]:
                errors.append(f"{pair['de']}: identical language versions need a real translation")
    for path in published_paths(root):
        name = path.relative_to(root).as_posix()
        if name not in registered:
            errors.append(f"{name}: published document has no registered DE/EN pair")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--manifest", type=Path, default=Path("docs/languages.json"))
    args = parser.parse_args()
    try:
        errors = check(args.root, args.root / args.manifest)
    except (OSError, ValueError, KeyError, UnicodeError) as error:
        print(f"doc-languages: invalid setup: {error}", file=sys.stderr)
        return 2
    for error in errors:
        print(f"doc-languages: {error}", file=sys.stderr)
    if errors:
        return 1
    print("doc-languages: all published pairs present, reviewed digests and fenced examples match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
