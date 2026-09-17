package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// Dependency handling for agent bundles (SPEC-0432 §8).
//
// Two checks with deliberately different force:
//
//	declared, catalog says no        -> abort, nothing written   (AC-7)
//	declared, catalog unreachable    -> warn, keep packing       (AC-16, E-5)
//	mentioned in prose, not declared -> warn, keep packing       (AC-8)
//
// The asymmetry is the point. A catalog that denies a dependency has delivered
// knowledge; a catalog that cannot be reached has delivered nothing, and turning
// nothing into a verdict is how a gate ends up wrongly red. A wrongly red gate
// gets switched off, and then nothing is checked at all.

// catalogLookup answers whether kind:name is admitted. A non-nil error means
// the question could NOT be answered (network, auth, timeout): it is explicitly
// not the same as found=false.
type catalogLookup func(kind, name string) (found bool, err error)

// skillPathRe matches the ONE form that means "this agent reads that skill's
// files": a path into a skill directory. Measured over all 20 agents and 121
// installed skills on 2026-09-15: this form hits 2 agents, both real
// dependencies, zero false positives.
//
// The slash form (`Invoked by /session-review`) is deliberately NOT matched. It
// is the OPPOSITE direction, the skill calling the agent, and it would also
// match `/review` inside `/review-plan`. Matching any mention hits 8 of 20 and
// turns the warning into noise (SPEC-0432 §8, AC-15).
var skillPathRe = regexp.MustCompile(`skills/([a-z0-9][a-z0-9-]*)`)

type skillMention struct {
	name string
	line int
}

// parseDeclaredDeps turns frontmatter entries ("skill:didactic-session") into
// bundle dependencies. Rejects anything malformed BEFORE packing starts.
func parseDeclaredDeps(entries []string) ([]skillbundle.Dependency, error) {
	var out []skillbundle.Dependency
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		kind, name, ok := strings.Cut(e, ":")
		if !ok || kind == "" || name == "" {
			return nil, fmt.Errorf("bad depends_on entry %q (want \"art:name\", e.g. %q); no bundle written",
				e, "skill:didactic-session")
		}
		if !skillbundle.ValidKind(kind) || kind == "" {
			return nil, fmt.Errorf("bad depends_on kind %q in %q (want %q or %q); no bundle written",
				kind, e, skillbundle.KindSkill, skillbundle.KindAgent)
		}
		out = append(out, skillbundle.Dependency{Kind: kind, Name: name})
	}
	return out, nil
}

// scanSkillPathMentions returns every skill named in path form, with the line
// number, so a human can look instead of search. Deduplicated on first sight.
func scanSkillPathMentions(body []byte) []skillMention {
	var out []skillMention
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		for _, m := range skillPathRe.FindAllStringSubmatch(sc.Text(), -1) {
			if name := m[1]; !seen[name] {
				seen[name] = true
				out = append(out, skillMention{name: name, line: line})
			}
		}
	}
	return out
}

// checkAgentDeps runs both checks. It returns an error only for the one case
// that must stop the build: a declared dependency the catalog denies.
func checkAgentDeps(srcPath string, body []byte, declared []skillbundle.Dependency,
	lookup catalogLookup, stderr io.Writer) error {

	declaredNames := map[string]bool{}
	for _, d := range declared {
		declaredNames[d.Name] = true
	}

	for _, d := range declared {
		if lookup == nil {
			fmt.Fprintf(stderr, "    warn: %s:%s declared, but the catalog was not consulted; the check did not run\n",
				d.Kind, d.Name)
			continue
		}
		found, err := lookup(d.Kind, d.Name)
		switch {
		case err != nil:
			// AC-16 / E-5: no answer is not a "no".
			fmt.Fprintf(stderr, "    warn: could not ask the catalog about %s:%s (%v); the check did not run\n",
				d.Kind, d.Name, err)
		case !found:
			return fmt.Errorf("declared dependency %s:%s is not in the catalog; no bundle written",
				d.Kind, d.Name)
		}
	}

	// AC-8: mentioned in path form but never declared. Warning only, forever
	// (E-4): it names the line so a human decides in one pass.
	for _, m := range scanSkillPathMentions(body) {
		if !declaredNames[m.name] {
			fmt.Fprintf(stderr, "    warn: %s:%d mentions skills/%s but does not declare it\n",
				srcPath, m.line, m.name)
		}
	}
	return nil
}

// er1CatalogLookup is the real lookup: it asks the registry whether the bundle
// is admitted. Built lazily, and only when something is actually declared, so a
// skill publish and an agent without declarations stay network-free.
func er1CatalogLookup(target, context string) catalogLookup {
	return func(kind, name string) (bool, error) {
		cfg, err := resolveER1Config(target)
		if err != nil {
			return false, err
		}
		// The identifier carries the kind (SPEC-0432 §4): looking an agent up
		// by its bare name would find a same-named skill instead.
		ref := name
		if kind != "" && kind != skillbundle.KindSkill {
			ref = kind + ":" + name
		}
		view, err := registry.ShowSkill(cfg, context, ref)
		if err != nil {
			// Telling "not there" from "could not ask" is the whole of E-5,
			// so it hangs on a typed sentinel, never on an error string: a
			// reworded message would otherwise turn a miss into a warning and
			// let a broken bundle through in silence.
			if errors.Is(err, registry.ErrNotInRegistry) {
				return false, nil
			}
			return false, err
		}
		return view != nil, nil
	}
}
