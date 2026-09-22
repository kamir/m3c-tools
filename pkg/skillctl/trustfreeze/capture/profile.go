package capture

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

//go:embed profiles/*.yaml
var builtinProfiles embed.FS

// Profile errors.
var (
	ErrUnknownProfile = errors.New("capture: unknown profile")
	ErrInvalidProfile = errors.New("capture: invalid profile")
)

// RedactionPolicyDefault is the only redaction policy of this build: the
// default patterns of the redact package plus the home root literal.
const RedactionPolicyDefault = "default-v1"

// Profile is a versioned capture input (schema trust-freeze/profile/v1). The
// exact bytes it was parsed from are recorded in the bundle by digest.
type Profile struct {
	SchemaVersion string   `yaml:"schema_version"`
	ID            string   `yaml:"id"`
	Version       string   `yaml:"version"`
	Description   string   `yaml:"description"`
	Required      []string `yaml:"required"`
	Optional      []string `yaml:"optional"`
	// FailIfRequiredMissing must be true in this build: a missing required
	// probe always makes the capture incomplete.
	FailIfRequiredMissing bool   `yaml:"fail_if_required_missing"`
	RedactionPolicy       string `yaml:"redaction_policy"`

	digest string
}

// Digest returns "sha256:<hex>" of the bytes the profile was parsed from.
func (p Profile) Digest() string { return p.digest }

// Ref returns the profile reference recorded in capture.json.
func (p Profile) Ref() trustfreeze.ProfileRef {
	return trustfreeze.ProfileRef{ID: p.ID, Version: p.Version, Digest: p.digest}
}

// ProbeIDs returns the required and optional probe ids, sorted.
func (p Profile) ProbeIDs() []string {
	ids := append(append([]string{}, p.Required...), p.Optional...)
	sort.Strings(ids)
	return ids
}

// IsRequired reports whether id is a required probe of the profile.
func (p Profile) IsRequired(id string) bool {
	for _, r := range p.Required {
		if r == id {
			return true
		}
	}
	return false
}

// Has reports whether id is a probe of the profile.
func (p Profile) Has(id string) bool {
	for _, x := range p.ProbeIDs() {
		if x == id {
			return true
		}
	}
	return false
}

// ParseProfile decodes a profile strictly (unknown fields and a second YAML
// document are errors) and validates it.
func ParseProfile(b []byte) (Profile, error) {
	var p Profile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("%w: %w", ErrInvalidProfile, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Profile{}, fmt.Errorf("%w: more than one YAML document", ErrInvalidProfile)
	}
	if err := p.validate(); err != nil {
		return Profile{}, err
	}
	p.digest = trustfreeze.Digest(b)
	return p, nil
}

func (p Profile) validate() error {
	if err := trustfreeze.CheckSchema(p.SchemaVersion, trustfreeze.SchemaProfile); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProfile, err)
	}
	if !isProfileID(p.ID) {
		return fmt.Errorf("%w: id %q must be lowercase letters, digits and '-'", ErrInvalidProfile, p.ID)
	}
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("%w: %s: empty version", ErrInvalidProfile, p.ID)
	}
	if !p.FailIfRequiredMissing {
		return fmt.Errorf("%w: %s: fail_if_required_missing must be true in this version", ErrInvalidProfile, p.ID)
	}
	if p.RedactionPolicy != RedactionPolicyDefault {
		return fmt.Errorf("%w: %s: redaction policy %q is not implemented (only %q)", ErrInvalidProfile, p.ID, p.RedactionPolicy, RedactionPolicyDefault)
	}
	if len(p.Required) == 0 {
		return fmt.Errorf("%w: %s: no required probe", ErrInvalidProfile, p.ID)
	}
	seen := map[string]bool{}
	for _, id := range p.ProbeIDs() {
		if err := trustfreeze.ValidateProbeID(id); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalidProfile, p.ID, err)
		}
		if seen[id] {
			return fmt.Errorf("%w: %s: probe %s listed twice", ErrInvalidProfile, p.ID, id)
		}
		seen[id] = true
	}
	return nil
}

func isProfileID(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// BuiltinProfileIDs returns the ids of the embedded profiles, sorted.
func BuiltinProfileIDs() []string {
	entries, err := builtinProfiles.ReadDir("profiles")
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range entries {
		if name := e.Name(); strings.HasSuffix(name, ".yaml") {
			ids = append(ids, strings.TrimSuffix(name, ".yaml"))
		}
	}
	sort.Strings(ids)
	return ids
}

// BuiltinProfile loads an embedded profile by id. The id inside the file
// must match its name.
func BuiltinProfile(id string) (Profile, error) {
	if !isProfileID(id) {
		return Profile{}, fmt.Errorf("%w: %q", ErrUnknownProfile, id)
	}
	b, err := builtinProfiles.ReadFile(path.Join("profiles", id+".yaml"))
	if err != nil {
		return Profile{}, fmt.Errorf("%w: %q (built-in: %s)", ErrUnknownProfile, id, strings.Join(BuiltinProfileIDs(), ", "))
	}
	p, err := ParseProfile(b)
	if err != nil {
		return Profile{}, err
	}
	if p.ID != id {
		return Profile{}, fmt.Errorf("%w: file %s.yaml declares id %q", ErrInvalidProfile, id, p.ID)
	}
	return p, nil
}
