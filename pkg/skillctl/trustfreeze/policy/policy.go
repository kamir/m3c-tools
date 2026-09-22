// Package policy judges a Trust Freeze diff (SPEC-0469, TF-04). Evaluate is a
// pure function from a diff and a policy to a verdict: no clock, no IO, no OS
// command. The policy is data (schema trust-freeze/policy/v1, JSON or YAML),
// versioned by its id and bound into the verdict by its rules digest
// (SPEC-0469 R5).
//
// Every change of the diff yields exactly one finding. Among the rules that
// match a change the highest severity wins (SPEC-0469 R6); a change no rule
// matches gets the policy's default severity, so nothing is dropped and a
// collection gap is never read as "no drift" (SPEC-0469 R7). The fail-on
// threshold decides only Verdict.ThresholdExceeded (SPEC-0469 R8).
package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
)

// DefaultPolicyID is the id of the built-in policy.
const DefaultPolicyID = "trust-freeze/policy/default-v0"

// DefaultSeverityRuleID is the RuleID of a finding that no rule matched; it
// got the policy's default severity. No rule may use this id.
const DefaultSeverityRuleID = "default_severity"

// MaxPolicyFileBytes caps a policy file.
const MaxPolicyFileBytes = 1 << 20

// ErrInvalidPolicy is wrapped by every policy parse and validation failure.
var ErrInvalidPolicy = errors.New("policy: invalid policy")

//go:embed builtin/default-v0.json
var defaultV0JSON []byte

// Policy is a policy document (schema trust-freeze/policy/v1).
type Policy struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	Description   string `json:"description,omitempty"`
	// FailOn is the default threshold; the CLI flag --fail-on replaces it. It
	// is not part of the rules digest because it judges nothing.
	FailOn Threshold `json:"fail_on"`
	// DefaultSeverity is given to a change that no rule matches.
	DefaultSeverity trustfreeze.Severity `json:"default_severity"`
	Rules           []Rule               `json:"rules"`
}

// Rule assigns a severity to the changes it matches.
type Rule struct {
	ID          string               `json:"id"`
	Description string               `json:"description,omitempty"`
	Severity    trustfreeze.Severity `json:"severity"`
	Match       Match                `json:"match"`
}

// Match is a conjunction: a change matches when every condition that is set
// holds.
type Match struct {
	// ChangeKinds is required and must not be empty.
	ChangeKinds []compare.ChangeKind `json:"change_kinds"`
	// ArtifactIDs, when set, restricts the rule to these exact artifact ids.
	ArtifactIDs []string `json:"artifact_ids,omitempty"`
	// Required, when set, restricts a collection_gap rule to required (true)
	// or optional (false) probes. Only allowed when ChangeKinds is exactly
	// [collection_gap].
	Required *bool `json:"required,omitempty"`
	// GapCauses, when set, restricts a collection_gap rule to these causes
	// (trustfreeze.GapReasons). Only allowed when ChangeKinds is exactly
	// [collection_gap].
	GapCauses []string `json:"gap_causes,omitempty"`
	// GapStatuses, when set, restricts a collection_gap rule to gaps whose
	// recorded probe status is one of these; a gap without a status (no or
	// duplicate result) never matches. Only allowed when ChangeKinds is
	// exactly [collection_gap].
	GapStatuses []trustfreeze.ProbeStatus `json:"gap_statuses,omitempty"`
	// SubjectMismatchAllowed, when set, restricts a subject_changed rule to
	// diffs made with (true) or without (false) the explicit opt-in. Only
	// allowed when ChangeKinds is exactly [subject_changed].
	SubjectMismatchAllowed *bool `json:"subject_mismatch_allowed,omitempty"`
}

// only reports whether m matches exactly one change kind, k.
func (m Match) only(k compare.ChangeKind) bool {
	return len(m.ChangeKinds) == 1 && m.ChangeKinds[0] == k
}

// PolicyRef identifies the policy a verdict was computed with.
type PolicyRef struct {
	ID          string `json:"id"`
	RulesDigest string `json:"rules_digest"`
}

// DefaultPolicy returns the built-in policy trust-freeze/policy/default-v0.
// Each call parses the embedded file again, so callers may modify the result.
func DefaultPolicy() (Policy, error) {
	p, err := ParsePolicy(defaultV0JSON)
	if err != nil {
		return Policy{}, fmt.Errorf("built-in %s: %w", DefaultPolicyID, err)
	}
	if p.ID != DefaultPolicyID {
		return Policy{}, fmt.Errorf("%w: built-in policy declares id %q", ErrInvalidPolicy, p.ID)
	}
	return p, nil
}

// LoadPolicyFile reads a policy file. A .json file is decoded as JSON, a .yaml
// or .yml file as YAML; any other name is decoded as JSON when its first
// non-space byte is "{", else as YAML. The file must be a regular file of at
// most MaxPolicyFileBytes.
func LoadPolicyFile(path string) (Policy, error) {
	// Stat before opening: opening a FIFO or a device could block or have
	// side effects. After opening, the file must still be the same one.
	before, err := os.Stat(path)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	if !before.Mode().IsRegular() {
		return Policy{}, fmt.Errorf("%w: %s is not a regular file", ErrInvalidPolicy, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	if !fi.Mode().IsRegular() || !os.SameFile(before, fi) {
		return Policy{}, fmt.Errorf("%w: %s changed while it was opened", ErrInvalidPolicy, path)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxPolicyFileBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	if len(b) > MaxPolicyFileBytes {
		return Policy{}, fmt.Errorf("%w: %s is larger than %d bytes", ErrInvalidPolicy, path, MaxPolicyFileBytes)
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return parseJSONPolicy(b)
	case ".yaml", ".yml":
		return parseYAMLPolicy(b)
	}
	return ParsePolicy(b)
}

// ParsePolicy decodes a policy from JSON (first non-space byte "{") or YAML
// and validates it. Decoding is strict in both formats: unknown fields,
// unknown enum values, duplicate keys, non-integer numbers and trailing
// documents are errors.
func ParsePolicy(b []byte) (Policy, error) {
	if t := bytes.TrimLeft(b, " \t\r\n"); len(t) > 0 && t[0] == '{' {
		return parseJSONPolicy(b)
	}
	return parseYAMLPolicy(b)
}

func parseJSONPolicy(b []byte) (Policy, error) {
	if err := checkJSONDuplicateKeys(b); err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	var p Policy
	if err := trustfreeze.UnmarshalStrict(b, &p); err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func parseYAMLPolicy(b []byte) (Policy, error) {
	j, err := yamlToJSON(b)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	return parseJSONPolicy(j)
}

// Validate checks the policy: schema id, a non-empty id, a valid threshold and
// default severity, and well-formed rules with unique ids.
func (p Policy) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, a...))
	}
	if err := trustfreeze.CheckSchema(p.SchemaVersion, trustfreeze.SchemaPolicy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	if strings.TrimSpace(p.ID) == "" {
		return bad("empty id")
	}
	if !p.FailOn.Valid() {
		return bad("fail_on %q is not a threshold", p.FailOn)
	}
	if !p.DefaultSeverity.Valid() {
		return bad("default_severity %q is not a severity", p.DefaultSeverity)
	}
	if p.Rules == nil {
		return bad("rules list missing")
	}
	seen := map[string]bool{}
	for i, r := range p.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return bad("rule %d has an empty id", i)
		}
		if r.ID == DefaultSeverityRuleID {
			return bad("rule id %q is reserved", r.ID)
		}
		if seen[r.ID] {
			return bad("rule id %q appears more than once", r.ID)
		}
		seen[r.ID] = true
		if !r.Severity.Valid() {
			return bad("rule %s: severity %q is not a severity", r.ID, r.Severity)
		}
		if len(r.Match.ChangeKinds) == 0 {
			return bad("rule %s: match.change_kinds is empty", r.ID)
		}
		for _, k := range r.Match.ChangeKinds {
			if !k.Valid() {
				return bad("rule %s: change kind %q is not known", r.ID, k)
			}
		}
		for _, id := range r.Match.ArtifactIDs {
			if err := trustfreeze.ValidateArtifactID(id); err != nil {
				return bad("rule %s: %v", r.ID, err)
			}
		}
		gapOnly := r.Match.only(compare.ChangeCollectionGap)
		if r.Match.Required != nil && !gapOnly {
			return bad("rule %s: match.required needs change_kinds [collection_gap] only", r.ID)
		}
		if (r.Match.GapCauses != nil || r.Match.GapStatuses != nil) && !gapOnly {
			return bad("rule %s: match.gap_causes and match.gap_statuses need change_kinds [collection_gap] only", r.ID)
		}
		if (r.Match.GapCauses != nil && len(r.Match.GapCauses) == 0) || (r.Match.GapStatuses != nil && len(r.Match.GapStatuses) == 0) {
			return bad("rule %s: an empty match.gap_causes or match.gap_statuses matches nothing", r.ID)
		}
		for _, c := range r.Match.GapCauses {
			if !slices.Contains(trustfreeze.GapReasons(), c) {
				return bad("rule %s: gap cause %q is not known", r.ID, c)
			}
		}
		for _, st := range r.Match.GapStatuses {
			if !st.Valid() {
				return bad("rule %s: gap status %q is not a probe status", r.ID, st)
			}
		}
		if r.Match.SubjectMismatchAllowed != nil && !r.Match.only(compare.ChangeSubjectChanged) {
			return bad("rule %s: match.subject_mismatch_allowed needs change_kinds [subject_changed] only", r.ID)
		}
		if len(r.Match.ArtifactIDs) > 0 && slices.Contains(r.Match.ChangeKinds, compare.ChangeCollectionGap) {
			return bad("rule %s: a collection_gap has no artifact id, so match.artifact_ids cannot apply", r.ID)
		}
	}
	return nil
}

// RulesDigest returns "sha256:<hex>" over the canonical JSON of everything in
// the policy that judges: schema id, id, description, default severity and
// rules. FailOn is left out on purpose: a different threshold must not change
// which policy judged (SPEC-0469 R8).
func (p Policy) RulesDigest() (string, error) {
	rules := p.Rules
	if rules == nil {
		rules = []Rule{}
	}
	b, err := trustfreeze.MarshalCanonical(struct {
		SchemaVersion   string               `json:"schema_version"`
		ID              string               `json:"id"`
		Description     string               `json:"description"`
		DefaultSeverity trustfreeze.Severity `json:"default_severity"`
		Rules           []Rule               `json:"rules"`
	}{p.SchemaVersion, p.ID, p.Description, p.DefaultSeverity, rules})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	return trustfreeze.Digest(b), nil
}

// matches reports whether rule r matches change c.
func (r Rule) matches(c compare.Change) bool {
	if !slices.Contains(r.Match.ChangeKinds, c.Kind) {
		return false
	}
	if len(r.Match.ArtifactIDs) > 0 && !slices.Contains(r.Match.ArtifactIDs, c.ArtifactID) {
		return false
	}
	if r.Match.Required != nil && (c.Gap == nil || c.Gap.Required != *r.Match.Required) {
		return false
	}
	if len(r.Match.GapCauses) > 0 && (c.Gap == nil || !slices.Contains(r.Match.GapCauses, c.Gap.Cause)) {
		return false
	}
	if len(r.Match.GapStatuses) > 0 && (c.Gap == nil || !slices.Contains(r.Match.GapStatuses, c.Gap.Status)) {
		return false
	}
	if r.Match.SubjectMismatchAllowed != nil && c.SubjectMismatchAllowed != *r.Match.SubjectMismatchAllowed {
		return false
	}
	return true
}

// maxJSONDepth bounds the nesting of a JSON policy.
const maxJSONDepth = 32

// checkJSONDuplicateKeys refuses a JSON document in which an object repeats a
// key. encoding/json would silently keep the last value, so a policy could
// read differently to a human and to the evaluator.
func checkJSONDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return walkJSON(dec, 0)
}

func walkJSON(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("json: nesting deeper than %d", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		keys := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("json: %w", err)
			}
			k, _ := kt.(string)
			if keys[k] {
				return fmt.Errorf("json: duplicate key %q", k)
			}
			keys[k] = true
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	return nil
}
