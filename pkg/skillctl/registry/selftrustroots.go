package registry

// SPEC-0225 trust-roots for the `self` tenant — minimal, ER1-specific.
//
// The existing pkg/skillctl/verify TrustRoots schema assumes an HTTP registry
// URL (SPEC-0188's admission server) and refuses non-URL values. For the
// `self` tenant the "registry" is literally the string "self"; the YAML this
// loader reads is therefore deliberately small:
//
//   # ~/.claude/trust-roots.yaml (or wherever)
//   registry: self
//   pubkey_b64: BASE64-OF-RAW-ED25519-PUBLIC-KEY
//   fingerprint: sha256:<lowercase-hex>      # optional — recomputed on load if absent
//   governance_minimum: green                # green | yellow | red
//
// `10-keygen-and-trustroots.sh` writes this file on machine 1 and prints the
// fingerprint; the operator carries the file to machine 2 out-of-band and
// verifies the fingerprint by eye before any `pull` runs.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SelfTrustRoots is the loaded form of the file.
type SelfTrustRoots struct {
	Registry          string `yaml:"registry"`
	PubKeyB64         string `yaml:"pubkey_b64"`
	Fingerprint       string `yaml:"fingerprint,omitempty"`
	GovernanceMinimum string `yaml:"governance_minimum,omitempty"`

	// Path is the file the data was loaded from. Empty for in-memory tests.
	Path string `yaml:"-"`

	// Resolved pub key (computed once at Load).
	pub ed25519.PublicKey
}

// DefaultSelfTrustRootsPath is the conventional location.
func DefaultSelfTrustRootsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "trust-roots.yaml")
}

// LoadSelfTrustRoots reads the YAML file at path. Path == "" → default.
func LoadSelfTrustRoots(path string) (*SelfTrustRoots, error) {
	if path == "" {
		path = DefaultSelfTrustRootsPath()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trust-roots: open %s: %w", path, err)
	}
	var tr SelfTrustRoots
	if err := yaml.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("trust-roots: parse %s: %w", path, err)
	}
	tr.Path = path
	if strings.TrimSpace(tr.Registry) == "" {
		tr.Registry = "self"
	}
	if tr.GovernanceMinimum == "" {
		tr.GovernanceMinimum = "green"
	}
	if tr.PubKeyB64 == "" {
		return nil, fmt.Errorf("trust-roots: pubkey_b64 missing in %s", path)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tr.PubKeyB64))
	if err != nil {
		return nil, fmt.Errorf("trust-roots: pubkey_b64 not valid base64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trust-roots: pubkey size %d, want %d", len(pubBytes), ed25519.PublicKeySize)
	}
	tr.pub = ed25519.PublicKey(pubBytes)

	// Compute fingerprint (or check the one the file declares).
	computed := selfFingerprint(pubBytes)
	if tr.Fingerprint == "" {
		tr.Fingerprint = computed
	} else if !strings.EqualFold(tr.Fingerprint, computed) {
		return nil, fmt.Errorf("trust-roots: fingerprint mismatch in %s (file says %s, key hashes to %s)", path, tr.Fingerprint, computed)
	}
	return &tr, nil
}

// PubKey returns the loaded ed25519 public key.
func (t *SelfTrustRoots) PubKey() ed25519.PublicKey {
	if t == nil {
		return nil
	}
	return t.pub
}

// MeetsFloor reports whether the given governance level passes the
// trust-roots' governance_minimum. Permissiveness ordering:
//
//	green (strictest)  >  yellow  >  red (most permissive)
//
// So a minimum of "green" admits only green attestations; "yellow" admits
// green or yellow; "red" admits everything (in v1 we still reject the empty
// string — "no attestation yet" — at a higher layer).
func (t *SelfTrustRoots) MeetsFloor(level string) bool {
	rank := map[string]int{"green": 3, "yellow": 2, "red": 1}
	have := rank[level]
	want := rank[t.GovernanceMinimum]
	return have >= want && have > 0
}

func selfFingerprint(pub []byte) string {
	d := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(d[:])
}

// ErrTrustRootsMissing is returned by LoadSelfTrustRoots when the file is not
// found. Distinct from a parse error so the cmd handler can surface a clear
// "carry the trust-roots over from machine 1" message.
var ErrTrustRootsMissing = errors.New("trust-roots: file not present (carry it out-of-band from machine 1, then retry)")
