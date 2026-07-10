"""Markdown- and code-aware chunker (SPEC-0268).

Splits a file into overlapping windows while preserving a heading/symbol path
and 1-based line ranges, so search results can cite `path:line`.

- Markdown: split on ATX heading boundaries (fenced code blocks are ignored as
  heading sources), then window each section by characters with line-accurate
  overlap.
- Other files: treated as a single section keyed by the file path, then windowed.

A single physical line longer than max_chars is hard-wrapped into pieces (all
sharing that line number) so no chunk grossly exceeds max_chars — this both
keeps the embedder's sequence length bounded and avoids pathological chunks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_MD_EXT = (".md", ".markdown")


@dataclass
class Chunk:
    text: str
    heading: str
    line_start: int  # 1-based, inclusive
    line_end: int    # 1-based, inclusive


def _split_markdown_sections(lines):
    """Yield (heading_path, start_line, section_lines) tuples."""
    sections = []
    stack = []          # list of (level, title)
    cur = []
    cur_start = 1
    in_fence = False

    def heading_path():
        return " > ".join(t for _, t in stack)

    for idx, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            if not cur:
                cur_start = idx
            cur.append(line)
            continue

        m = None if in_fence else _HEADING_RE.match(line)
        if m:
            if cur:
                sections.append((heading_path(), cur_start, cur))
            level = len(m.group(1))
            title = m.group(2).strip()
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            cur = [line]
            cur_start = idx
        else:
            if not cur:
                cur_start = idx
            cur.append(line)

    if cur:
        sections.append((heading_path(), cur_start, cur))
    return sections


def _expand_units(section_lines, start_line, max_chars):
    """Return (line_no, piece) units, hard-wrapping any over-long line."""
    units = []
    for off, line in enumerate(section_lines):
        ln = start_line + off
        if max_chars <= 0 or len(line) <= max_chars:
            units.append((ln, line))
        else:
            for s in range(0, len(line), max_chars):
                units.append((ln, line[s:s + max_chars]))
    return units


def _window(section_lines, start_line, heading, max_chars, overlap_chars):
    units = _expand_units(section_lines, start_line, max_chars)
    out = []
    n = len(units)
    i = 0
    while i < n:
        j = i
        clen = 0
        while j < n:
            add = len(units[j][1]) + 1
            if j > i and clen + add > max_chars:
                break
            clen += add
            j += 1
        if j == i:               # safety: always make progress
            j = i + 1
        text = "\n".join(u[1] for u in units[i:j])
        out.append(Chunk(text=text, heading=heading,
                         line_start=units[i][0], line_end=units[j - 1][0]))
        if j >= n:
            break
        # step back to create overlap, but guarantee forward progress
        back = 0
        bchars = 0
        while back < (j - i - 1) and bchars < overlap_chars:
            bchars += len(units[j - 1 - back][1]) + 1
            back += 1
        next_i = j - back
        if next_i <= i:
            next_i = i + 1
        i = next_i
    return out


def chunk_file(relpath, text, max_chars=1500, overlap_chars=200):
    lines = text.split("\n")
    low = relpath.lower()
    if low.endswith(_MD_EXT):
        sections = _split_markdown_sections(lines)
    else:
        sections = [(relpath, 1, lines)]

    chunks = []
    for heading, start_line, sec_lines in sections:
        chunks.extend(_window(sec_lines, start_line, heading or relpath,
                              max_chars, overlap_chars))
    return [c for c in chunks if c.text.strip()]
