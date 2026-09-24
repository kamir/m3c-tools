package compare

import (
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// Normalization rule set ids. A rule set is versioned data: changing what
// counts as volatile means a new id, never an edit of an existing one
// (SPEC-0469 R4).
const (
	RuleSetNormalizeV1 = "trust-freeze/normalize/v1"
	// RuleSetNormalizeV2 adds the two volatile values the Linux network
	// probes brought (SPEC-0471 TF06-R3): the metric of a route, which the
	// network stack rewrites without the route changing, and the resolver
	// systemd-resolved happens to be querying, which it picks out of the
	// configured list at runtime. v1 is shipped unchanged so that a diff
	// recorded with it stays readable.
	RuleSetNormalizeV2 = "trust-freeze/normalize/v2"
	DefaultRuleSetID   = RuleSetNormalizeV2
)

// ErrUnknownRuleSet is returned for a rule set id this build does not ship.
var ErrUnknownRuleSet = errors.New("compare: unknown normalization rule set")

//go:embed rules/normalize-v1.json
var normalizeV1JSON []byte

//go:embed rules/normalize-v2.json
var normalizeV2JSON []byte

var ruleSetFiles = map[string][]byte{
	RuleSetNormalizeV1: normalizeV1JSON,
	RuleSetNormalizeV2: normalizeV2JSON,
}

// RuleSetIDs returns the ids of the rule sets this build ships, sorted. A diff
// names the one it was computed with, so an older id has to stay loadable for
// that diff to remain readable.
func RuleSetIDs() []string {
	out := make([]string, 0, len(ruleSetFiles))
	for id := range ruleSetFiles {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// RuleSet names the volatile values that are removed before two artifacts are
// compared. It removes nothing else, so no finding can be normalized away.
type RuleSet struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	// VolatileFields are artifact field names (see ComparedFields) that are
	// not compared.
	VolatileFields []string `json:"volatile_fields"`
	// VolatileAttributes are exact attribute keys that are dropped from
	// Artifact.Attributes before comparing and before digesting.
	VolatileAttributes []string `json:"volatile_attributes"`
}

// comparedField is one scalar artifact field that a "changed" entry can name.
type comparedField struct {
	name string
	get  func(trustfreeze.Artifact) string
}

// comparedFields lists, in sort order, the artifact fields compare looks at
// besides the attributes. State and confidence are not listed: they have
// their own change kinds (a state change that neither starts nor ends at
// observed is reported as the field "state" of a "changed" entry). The stored
// Artifact.Digest is never compared: it covers the raw attributes, volatile
// ones included, and compare recomputes digests over normalized attributes.
var comparedFields = []comparedField{
	{"provenance.method", func(a trustfreeze.Artifact) string { return a.Provenance.Method }},
	{"provenance.observed_at", func(a trustfreeze.Artifact) string { return a.Provenance.ObservedAt }},
	{"provenance.sources", func(a trustfreeze.Artifact) string {
		s := slices.Clone(a.Provenance.Sources)
		slices.Sort(s)
		return strings.Join(s, "\x00")
	}},
	{"provenance.tool_version", func(a trustfreeze.Artifact) string { return a.Provenance.ToolVersion }},
	{"scope", func(a trustfreeze.Artifact) string { return a.Scope }},
	{"sensitivity", func(a trustfreeze.Artifact) string { return string(a.Sensitivity) }},
	{"source", func(a trustfreeze.Artifact) string { return a.Source }},
	{"type", func(a trustfreeze.Artifact) string { return a.Type }},
}

// ComparedFields returns the names of the artifact fields compare can report
// in Change.ChangedFields, "state" included, sorted.
func ComparedFields() []string {
	out := make([]string, 0, len(comparedFields)+1)
	for _, f := range comparedFields {
		out = append(out, f.name)
	}
	out = append(out, "state")
	slices.Sort(out)
	return out
}

// LoadRuleSet returns the built-in rule set with the given id; an empty id
// selects DefaultRuleSetID.
func LoadRuleSet(id string) (RuleSet, error) {
	if id == "" {
		id = DefaultRuleSetID
	}
	b, ok := ruleSetFiles[id]
	if !ok {
		return RuleSet{}, fmt.Errorf("%w: %q", ErrUnknownRuleSet, id)
	}
	var rs RuleSet
	// Strict decode, but whitespace-tolerant: a CRLF checkout of the embedded
	// file must not change behavior. The digest is computed over the
	// canonical form, never over the file bytes.
	if err := trustfreeze.UnmarshalStrict(b, &rs); err != nil {
		return RuleSet{}, fmt.Errorf("%w: %q: %w", ErrUnknownRuleSet, id, err)
	}
	if rs.ID != id {
		return RuleSet{}, fmt.Errorf("%w: file for %q declares id %q", ErrUnknownRuleSet, id, rs.ID)
	}
	if err := rs.Validate(); err != nil {
		return RuleSet{}, err
	}
	return rs, nil
}

// Validate checks that the rule set names only known fields and that both
// lists are sorted, free of duplicates and of empty entries.
func (r RuleSet) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%w: empty rule set id", ErrUnknownRuleSet)
	}
	known := ComparedFields()
	for _, f := range r.VolatileFields {
		if f == "state" || !slices.Contains(known, f) {
			return fmt.Errorf("%w: %s: field %q cannot be volatile", ErrUnknownRuleSet, r.ID, f)
		}
	}
	lists := []struct {
		name string
		list []string
	}{{"volatile_fields", r.VolatileFields}, {"volatile_attributes", r.VolatileAttributes}}
	for _, l := range lists {
		for i, v := range l.list {
			if v == "" {
				return fmt.Errorf("%w: %s: empty entry in %s", ErrUnknownRuleSet, r.ID, l.name)
			}
			if i > 0 && l.list[i-1] >= v {
				return fmt.Errorf("%w: %s: %s must be sorted and unique", ErrUnknownRuleSet, r.ID, l.name)
			}
		}
	}
	return nil
}

// Digest returns "sha256:<hex>" over the canonical JSON of the rule set. A diff
// records it next to the id, so the exact rules it was computed with are
// provable.
func (r RuleSet) Digest() (string, error) {
	if r.VolatileFields == nil {
		r.VolatileFields = []string{}
	}
	if r.VolatileAttributes == nil {
		r.VolatileAttributes = []string{}
	}
	b, err := trustfreeze.MarshalCanonical(r)
	if err != nil {
		return "", err
	}
	return trustfreeze.Digest(b), nil
}

// NormalizeAttributes returns a copy of attrs without the volatile attribute
// keys. A nil map yields an empty map.
func (r RuleSet) NormalizeAttributes(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		if slices.Contains(r.VolatileAttributes, k) {
			continue
		}
		out[k] = v
	}
	return out
}

// volatileField reports whether the artifact field name is not compared.
func (r RuleSet) volatileField(name string) bool {
	return slices.Contains(r.VolatileFields, name)
}
