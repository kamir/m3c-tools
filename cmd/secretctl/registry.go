package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// The registry of secrets and the places that hold them (SPEC-0438 §3).
//
// It holds NO values, only locations. That is what makes it checkable into git:
// the question "who holds this secret" must be answerable by reading, and it
// was not answerable on 2026-09-15, which is how one value stayed public and
// valid for four and a half months (BUG-0439).

const registrySchema = "m3c-secret-registry/v1"

// Source is where the authoritative value lives.
type Source struct {
	Kind    string `yaml:"kind"`    // gcp-secret-manager
	Project string `yaml:"project"` // GCP project
	Secret  string `yaml:"secret"`  // secret name in the store
}

// Holder is one place that carries a copy. Every place is named INDIVIDUALLY.
// A collective entry like "the config files" is exactly the hole this registry
// exists to close, so the loader refuses one (see Validate).
type Holder struct {
	ID   string `yaml:"id"`
	Kind string `yaml:"kind"` // macos-keychain | file | cloud-run
	Host string `yaml:"host"` // empty or the local hostname means local

	// macos-keychain
	Service string `yaml:"service,omitempty"`

	// file
	Path string `yaml:"path,omitempty"`
	Key  string `yaml:"key,omitempty"` // NAME= prefix inside the file

	// cloud-run and cloud-scheduler
	Project  string `yaml:"project,omitempty"`
	Region   string `yaml:"region,omitempty"`
	Service_ string `yaml:"service_name,omitempty"`
	Env      string `yaml:"env,omitempty"`

	// cloud-scheduler: the job carries the value in a request header, in
	// plaintext, inside the job definition. Found on 2026-09-15: all five
	// jobs did, and none of them was in the first inventory.
	Job    string `yaml:"job,omitempty"`
	Header string `yaml:"header,omitempty"`

	// docker: a running container carries it in its environment. Two did.
	Container string `yaml:"container,omitempty"`
}

// Probe says how to ask a service whether a value is accepted.
type Probe struct {
	Kind          string `yaml:"kind"` // http
	URL           string `yaml:"url"`
	Header        string `yaml:"header"` // X-API-KEY
	ExpectOK      int    `yaml:"expect_ok"`
	ExpectRevoked int    `yaml:"expect_revoked"`
}

// Role is what a secret is USED FOR, and what happens to that use when the
// value changes (SPEC-0438 §8b).
//
// The inventory alone answers "who holds this". That is not enough, and
// 2026-09-15 proved it: ER1_API_KEY authenticated service clients AND, through
// an undeclared fallback in get_token_secret(), signed every device token.
// Rotating it silently invalidated every token issued before. The inventory had
// found all fifteen holders and none of the consequences, because a holder is a
// PLACE and this was a USE.
//
// A role is therefore not documentation. It is the answer to "what breaks when
// I turn this", asked before turning it rather than after.
type Role struct {
	ID          string `yaml:"id"`
	Was         string `yaml:"was"`          // what the secret does in this role
	BeiRotation string `yaml:"bei_rotation"` // what a rotation does to it
}

// Entry is one managed secret.
type Entry struct {
	Name    string   `yaml:"name"`
	Summary string   `yaml:"summary"`
	Prefix  string   `yaml:"prefix,omitempty"` // SPEC-0438 §5, e.g. "m3cer1_"
	Source  Source   `yaml:"source"`
	Roles   []Role   `yaml:"roles"`
	Holders []Holder `yaml:"holders"`
	Probe   Probe    `yaml:"probe"`
}

// Registry is the whole file.
type Registry struct {
	Schema  string  `yaml:"schema"`
	Secrets []Entry `yaml:"secrets"`
}

// DefaultRegistryPath is where the registry lives when nothing else is said.
func DefaultRegistryPath() string {
	if p := os.Getenv("SECRETCTL_REGISTRY"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "m3c", "secrets.yaml")
}

// LoadRegistry reads and validates the file.
func LoadRegistry(path string) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry %s: %w", path, err)
	}
	var r Registry
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("registry %s: %w", path, err)
	}
	if r.Schema != registrySchema {
		return nil, fmt.Errorf("registry %s: schema %q, want %q", path, r.Schema, registrySchema)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("registry %s: %w", path, err)
	}
	return &r, nil
}

// Find returns one entry by name.
func (r *Registry) Find(name string) (*Entry, error) {
	for i := range r.Secrets {
		if r.Secrets[i].Name == name {
			return &r.Secrets[i], nil
		}
	}
	var known []string
	for _, e := range r.Secrets {
		known = append(known, e.Name)
	}
	return nil, fmt.Errorf("no secret named %q (known: %s)", name, strings.Join(known, ", "))
}

// collectiveWords are the shapes a forgotten place hides behind. A registry
// that says "the config files" answers the question it exists to answer with a
// gesture, and the next rotation then fails at the copy nobody listed
// (SPEC-0438 AC-3).
var collectiveWords = []string{"*", "alle", "all ", "die konfigurationen", "etc.", "usw", "..."}

// Validate refuses a registry that cannot carry a rotation.
func (r *Registry) Validate() error {
	seenSecret := map[string]bool{}
	for _, e := range r.Secrets {
		if e.Name == "" {
			return fmt.Errorf("a secret has no name")
		}
		if seenSecret[e.Name] {
			return fmt.Errorf("secret %q listed twice", e.Name)
		}
		seenSecret[e.Name] = true
		if len(e.Holders) == 0 {
			return fmt.Errorf("secret %q lists no holders; a secret with no known holders cannot be rotated", e.Name)
		}
		if len(e.Roles) == 0 {
			return fmt.Errorf("secret %q names no roles; without them a rotation cannot say what it breaks "+
				"(SPEC-0438 §8b: ER1_API_KEY silently signed device tokens, and the inventory did not know)", e.Name)
		}
		for _, r := range e.Roles {
			if r.ID == "" || r.Was == "" || r.BeiRotation == "" {
				return fmt.Errorf("secret %q: role %q needs id, was and bei_rotation; "+
					"a role without its rotation consequence is a label, not a warning", e.Name, r.ID)
			}
		}
		seenHolder := map[string]bool{}
		for _, h := range e.Holders {
			if h.ID == "" {
				return fmt.Errorf("secret %q: a holder has no id", e.Name)
			}
			if seenHolder[h.ID] {
				return fmt.Errorf("secret %q: holder %q listed twice", e.Name, h.ID)
			}
			seenHolder[h.ID] = true
			if err := h.validate(e.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h Holder) validate(secretName string) error {
	blob := strings.ToLower(h.ID + " " + h.Path + " " + h.Service + " " + h.Service_)
	for _, w := range collectiveWords {
		if strings.Contains(blob, w) {
			return fmt.Errorf("secret %q: holder %q reads as a collective (%q); "+
				"name every place individually, a rotation fails at the copy nobody listed",
				secretName, h.ID, w)
		}
	}
	switch h.Kind {
	case "macos-keychain":
		if h.Service == "" {
			return fmt.Errorf("secret %q: holder %q needs a keychain service", secretName, h.ID)
		}
	case "file":
		if h.Path == "" || h.Key == "" {
			return fmt.Errorf("secret %q: holder %q needs both path and key", secretName, h.ID)
		}
	case "cloud-scheduler":
		if h.Project == "" || h.Region == "" || h.Job == "" || h.Header == "" {
			return fmt.Errorf("secret %q: holder %q needs project, region, job and header", secretName, h.ID)
		}
	case "docker":
		if h.Container == "" || h.Env == "" {
			return fmt.Errorf("secret %q: holder %q needs container and env", secretName, h.ID)
		}
	case "cloud-run":
		if h.Project == "" || h.Service_ == "" || h.Env == "" || h.Region == "" {
			// Region included on purpose: it was hardcoded to europe-west3 in
			// the first draft while the services actually run in
			// europe-north1, and the inventory then reported all three as
			// unreadable. A guess in the source is a lie in the table.
			return fmt.Errorf("secret %q: holder %q needs project, region, service_name and env", secretName, h.ID)
		}
	default:
		return fmt.Errorf("secret %q: holder %q has unknown kind %q", secretName, h.ID, h.Kind)
	}
	return nil
}

// IsLocal reports whether this holder sits on the machine running the command.
func (h Holder) IsLocal() bool {
	if h.Host == "" {
		return true
	}
	name, err := os.Hostname()
	if err != nil {
		return false
	}
	short := name
	if i := strings.IndexByte(short, '.'); i > 0 {
		short = short[:i]
	}
	return h.Host == name || h.Host == short
}
