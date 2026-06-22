---
name: pdf-build
version: 2.1.0
description: Generate a branded PDF from a markdown file using pandoc and XeLaTeX.
allowed-tools:
  - Bash
  - Read
governance_level: green
---

# pdf-build

Compile a markdown document into a polished PDF.

## Workflow

1. Read the source markdown and its YAML frontmatter (title, author, date).
2. Invoke pandoc with the corporate LaTeX template.
3. Produce a table of contents, page breaks per section, and syntax-highlighted
   code blocks.

The build is fully local. Fonts and the template live in the repository. The
output PDF is written next to the source file.
