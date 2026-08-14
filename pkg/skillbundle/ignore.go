package skillbundle

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Pack-time ignore rules (SPEC-0188 §3.4).
//
// A skill bundle is source, not build output. Compiled binaries, dependency
// trees, and caches (a `dist/` executable, `node_modules/`, `__pycache__/`) can
// dwarf the actual skill by three orders of magnitude and blow the registry's
// inline-admit cap — while adding nothing a consumer needs (they rebuild locally
// from the packed source). `collectFiles` therefore skips a small, conservative
// set of well-known artifact paths, plus any patterns a skill declares in a
// top-level `.skbignore`.
//
// This trims the *packed content only*. It is deterministic (the default list is
// constant; `.skbignore` is read once, before the lexical walk), so the SPEC-0188
// §3 digest stays reproducible. Two invariants keep it safe:
//   - the required top-level `SKILL.md` is NEVER ignored (guarded in collectFiles);
//   - `.skbignore` may *re-include* a default-ignored path with a `!pattern`.
//
// Pattern language — a deliberate, documented subset of gitignore:
//   - blank lines and lines beginning with `#` are comments;
//   - a leading `!` negates (re-includes) a match;
//   - a trailing `/` restricts the rule to directories;
//   - a pattern with NO interior `/` matches by BASENAME at any depth
//     (`node_modules/`, `*.pyc`);
//   - a pattern with an interior or leading `/` is ANCHORED to the skill root and
//     matched against the whole relative path;
//   - globs use path.Match semantics (`*`, `?`, `[…]`) — there is no `**`.
// Last matching rule wins (gitignore order). As in gitignore, a file cannot be
// re-included once a parent directory is ignored (the walk prunes the subtree),
// so negate the directory, not a file beneath it.
//
// defaultIgnorePatterns is intentionally limited to paths that are unambiguously
// build output / VCS / tool cache. Anything a specific skill needs kept can be
// re-included via `.skbignore` (`!dist/` etc.). Keep this list conservative:
// a false exclude silently ships a broken skill.
var defaultIgnorePatterns = []string{
	// dependency trees & build output
	"node_modules/",
	"dist/",
	"build/",
	"target/",
	// version control & editor cruft
	".git/",
	".svn/",
	".DS_Store",
	// language caches / virtual envs
	"__pycache__/",
	".venv/",
	"venv/",
	".pytest_cache/",
	".mypy_cache/",
	".ruff_cache/",
	"*.pyc",
	"*.pyo",
}

// ignoreRule is one parsed pattern.
type ignoreRule struct {
	glob     string // path.Match glob (basename or anchored rel path)
	dirOnly  bool   // trailing "/" — matches directories only
	negate   bool   // leading "!" — re-includes
	anchored bool   // contained/leading "/" — match the full rel path, not the basename
}

// parseIgnoreLine parses one pattern line. ok=false for blanks/comments.
func parseIgnoreLine(line string) (ignoreRule, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ignoreRule{}, false
	}
	var r ignoreRule
	if strings.HasPrefix(line, "!") {
		r.negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	if strings.HasPrefix(line, "/") {
		r.anchored = true
		line = strings.TrimPrefix(line, "/")
	}
	if strings.Contains(line, "/") {
		r.anchored = true
	}
	if line == "" {
		return ignoreRule{}, false
	}
	r.glob = line
	return r, true
}

// parseIgnore compiles a list of pattern lines to rules, preserving order.
func parseIgnore(lines []string) []ignoreRule {
	rules := make([]ignoreRule, 0, len(lines))
	for _, ln := range lines {
		if r, ok := parseIgnoreLine(ln); ok {
			rules = append(rules, r)
		}
	}
	return rules
}

// loadIgnoreRules returns the default artifact rules followed by any rules from
// a top-level `.skbignore` in skillDir (so a skill's rules — including negations —
// take precedence via last-match-wins).
func loadIgnoreRules(skillDir string) []ignoreRule {
	rules := parseIgnore(defaultIgnorePatterns)
	if data, err := os.ReadFile(filepath.Join(skillDir, ".skbignore")); err == nil {
		rules = append(rules, parseIgnore(strings.Split(string(data), "\n"))...)
	}
	return rules
}

// ignored reports whether rel (a slash-separated path relative to the skill root)
// is excluded from the bundle. Last matching rule wins.
func ignored(rules []ignoreRule, rel string, isDir bool) bool {
	res := false
	base := path.Base(rel)
	for _, r := range rules {
		if r.dirOnly && !isDir {
			continue
		}
		target := base
		if r.anchored {
			target = rel
		}
		if ok, err := path.Match(r.glob, target); err == nil && ok {
			res = !r.negate
		}
	}
	return res
}
