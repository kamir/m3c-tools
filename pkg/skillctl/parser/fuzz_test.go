package parser

// Native Go fuzz target for the SKILL.md frontmatter parser. The whole file
// (delimiters + embedded YAML block) is untrusted author input. Oracle: Parse
// never panics on any byte sequence: a malformed delimiter run or a hostile
// YAML block must surface as an error/no-frontmatter, never a crash.

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse drives Parse with fuzzed markdown+frontmatter bytes. Seeds reuse the
// real adversarial + benign SKILL.md corpus under pkg/skillctl/bodyscan/testdata
// (every file there opens with a --- frontmatter block) plus hand-crafted
// delimiter edge cases. Oracle: never panics.
func FuzzParse(f *testing.F) {
	// Reuse the bodyscan corpus (relative to this package dir) as realistic seeds.
	for _, sub := range []string{"adversarial", "benign"} {
		glob := filepath.Join("..", "bodyscan", "testdata", "corpus", sub, "*.md")
		matches, _ := filepath.Glob(glob)
		for _, p := range matches {
			if b, err := os.ReadFile(p); err == nil {
				f.Add(b)
			}
		}
	}

	// Delimiter / YAML edge cases.
	f.Add([]byte("---\nname: x\nversion: 1.0.0\n---\nbody text"))
	f.Add([]byte("---\r\nname: x\r\n---\r\nbody"))       // CRLF
	f.Add([]byte("---\nname: x\nno closing delimiter"))  // unterminated
	f.Add([]byte("---\n: : :\n---\n"))                    // broken YAML block
	f.Add([]byte("---\nmetadata:\n  a: [1,2,3]\n---\n"))  // nested
	f.Add([]byte("---"))                                  // just the opener
	f.Add([]byte("------\n---\n"))                        // dashes soup
	f.Add([]byte("no frontmatter here"))
	f.Add([]byte(""))
	f.Add([]byte("---\n\n---\n"))                         // empty YAML block

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Parse(data) // must never panic
	})
}
