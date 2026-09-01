---
name: json-pretty
version: 1.0.0
description: Pretty-print and validate a JSON file, reporting the first parse error.
allowed-tools:
  - Read
  - Write
governance_level: green
---

# json-pretty

Format and validate JSON.

The skill reads a JSON file, validates it, and rewrites it with two-space
indentation. If parsing fails it reports the line and column of the first error
and leaves the original untouched. It is a pure local formatter — no decoding
tricks, no network, no surprises.
