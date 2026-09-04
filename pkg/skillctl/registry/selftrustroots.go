package registry

// SPEC-0225 trust-roots for the `self` tenant: minimal, ER1-specific.
//
// The existing pkg/skillctl/verify TrustRoots schema assumes an HTTP registry
// URL (SPEC-0188's admission server) and refuses non-URL values. For the
// `self` tenant the "registry" is literally the string "self"; the YAML this
// loader reads is therefore deliberately small:
//
//   # ~/.claude/trust-roots.yaml (or wherever)
//   registry: self
//   pubkey_b64: BASE64-OF-RAW-ED25519-PUBLIC-KEY
//   fingerprint: sha256:<lowercase-hex>      # optional: recomputed on load if absent
//   governance_minimum: green                # green | yellow  ("red" is NOT a
//                                            # valid floor: it would admit
//                                            # everything; rejected on load)
//
// `10-keygen-and-trustroots.sh` writes this file on machine 1 and prints the
// fingerprint; the operator carries the file to machine 2 out-of-band and
// verifies the fingerprint by eye before any `pull` runs.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/govlevel"
	"gopkg.in/yaml.v3"
)

// SelfTrustRoots is the loaded form of the file.
type SelfTrustRoots struct {
	Registry          string `yaml:"registry"`
	PubKeyB64         string `yaml:"pubkey_b64"`
	Fingerprint       string `yaml:"fingerprint,omitempty"`
	GovernanceMinimum string `yaml:"governance_minimum,omitempty"`

	// SPEC-0359 D3 (federation): N-of-M co-attestation. GovernanceQuorum is the
	// number of DISTINCT pinned signer keys whose attestation must meet the floor
	// (default 1 → today's single-attestation behaviour). Signers is the pinned
	// reviewer key set; empty → one implicit signer {"", pub} matching any
	// reviewer_id (byte-identical to pre-D3). Both omitempty for schema stability.
	GovernanceQuorum int      `yaml:"governance_quorum,omitempty"`
	Signers          []Signer `yaml:"signers,omitempty"`

	// D3(i) cross-signing: pin ONE governance root + a path of signed
	// cross-signature records; verified, unexpired members are added to the
	// signer set at load. Lets you trust a group without listing every member key.
	GovernanceRootPubKeyB64 string `yaml:"governance_root_pubkey_b64,omitempty"`
	CrossSignPath           string `yaml:"cross_sign_path,omitempty"`

	// Path is the file the data was loaded from. Empty for in-memory tests.
	Path string `yaml:"-"`

	// Resolved pub key (computed once at Load).
	pub ed25519.PublicKey
}

// quorum returns the required number of distinct qualifying signers (>= 1).
func (t *SelfTrustRoots) quorum() int {
	if t == nil || t.GovernanceQuorum < 1 {
		return 1
	}
	return t.GovernanceQuorum
}

// signerSet returns the pinned reviewer keys, or a single implicit signer bound
// to the primary key (ReviewerID "" matches any reviewer_id) when none are
// pinned: the D3-off default that reproduces the single-key gauntlet exactly.
func (t *SelfTrustRoots) signerSet() []Signer {
	if len(t.Signers) > 0 {
		return t.Signers
	}
	return []Signer{{ReviewerID: "", pub: t.pub}}
}

// MeetsQuorum reports whether at least `quorum()` of the given per-signer levels
// meet the floor. MeetsFloor keeps its exact per-level semantics; this only
// aggregates over it, so the artifact.TrustProvider interface is untouched.
func (t *SelfTrustRoots) MeetsQuorum(levels []string) bool {
	n := 0
	for _, l := range levels {
		if t.MeetsFloor(l) {
			n++
		}
	}
	return n >= t.quorum()
}

// DefaultSelfTrustRootsPath is the conventional location.
func DefaultSelfTrustRootsPath() string {
	return filepath.Join(userHome(), ".claude", "trust-roots.yaml")
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
	// Strict mode: unknown/typo'd YAML fields are rejected. A misspelled key
	// (e.g. `governance_minumum:`) would otherwise be silently ignored, leaving
	// the floor at its default and masking an operator error. Matches the
	// SPEC-0188 strict loader in verify/trustroots.go.
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // strict: unknown fields → error
	if err := dec.Decode(&tr); err != nil {
		return nil, fmt.Errorf("trust-roots: parse %s: %w", path, err)
	}
	tr.Path = path
	if strings.TrimSpace(tr.Registry) == "" {
		tr.Registry = "self"
	}
	if tr.GovernanceMinimum == "" {
		tr.GovernanceMinimum = "green"
	}
	// Reject an invalid governance floor via the ONE shared guard (SPEC-0252
	// §6): "red" is NOT a valid floor (the most-permissive rung would admit
	// every attestation, defeating the gate) and unknown/typo'd values fail
	// loudly. ValidFloor returns the normalized form; storing it (SEC-L1) keeps
	// MeetsFloor's rank from collapsing on a mixed-case floor.
	norm, ok := govlevel.ValidFloor(tr.GovernanceMinimum)
	if !ok {
		return nil, fmt.Errorf("trust-roots: governance_minimum %q is not one of [green, yellow] in %s", tr.GovernanceMinimum, path)
	}
	tr.GovernanceMinimum = norm
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

	if err := tr.resolveSigners(path); err != nil {
		return nil, err
	}

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
// resolveSigners turns the DECLARED D3 fields into verifying keys: it decodes
// each pinned signer key, admits cross-signed members from the pinned governance
// root, and refuses a quorum the pinned set cannot satisfy.
//
// It is one shared method because there are now TWO carriers of the same
// declaration: the hand-written trust-roots file (LoadSelfTrustRoots) and a
// pinned peer (Peer.AsTrustRoots, FR-0115). A second copy would be a second
// place for the two to drift, and the drift would be SILENT: an unresolved
// signer key does not fail, it simply never matches an attestation, so the pull
// reports "no attestation at or above the governance_minimum" while the
// attestation sits right there in the registry.
//
// source names the origin (a file path, or a peer name) for error messages.
func (t *SelfTrustRoots) resolveSigners(source string) error {
	for i := range t.Signers {
		sb, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(t.Signers[i].PubKeyB64))
		if derr != nil {
			return fmt.Errorf("trust-roots: signer %q pubkey_b64 not valid base64: %w", t.Signers[i].ReviewerID, derr)
		}
		if len(sb) != ed25519.PublicKeySize {
			return fmt.Errorf("trust-roots: signer %q pubkey size %d, want %d", t.Signers[i].ReviewerID, len(sb), ed25519.PublicKeySize)
		}
		t.Signers[i].pub = ed25519.PublicKey(sb)
	}
	// D3(i): admit cross-signed members from the PINNED governance root.
	if t.GovernanceRootPubKeyB64 != "" && t.CrossSignPath != "" {
		gpub, gerr := base64.StdEncoding.DecodeString(strings.TrimSpace(t.GovernanceRootPubKeyB64))
		if gerr != nil || len(gpub) != ed25519.PublicKeySize {
			return fmt.Errorf("trust-roots: governance_root_pubkey_b64 invalid in %s", source)
		}
		records, rerr := loadCrossSignRecords(t.CrossSignPath)
		if rerr != nil {
			return fmt.Errorf("trust-roots: cross_sign_path %s: %w", t.CrossSignPath, rerr)
		}
		t.Signers = append(t.Signers, DeriveCrossSignedSigners(ed25519.PublicKey(gpub), records, time.Now())...)
	}
	if t.GovernanceQuorum > 1 && len(t.Signers) < t.GovernanceQuorum {
		return fmt.Errorf("trust-roots: governance_quorum %d exceeds the %d pinned signers in %s", t.GovernanceQuorum, len(t.Signers), source)
	}
	return nil
}

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
// green or yellow. A loaded floor is always "green" or "yellow": LoadSelfTrustRoots
// rejects "red" (and any other value) because "red" as a floor would admit
// everything. The rank for "red" below remains, but only as a ranking of an
// incoming attestation level, never as a configured minimum. (We still reject
// the empty string, "no attestation yet", at a higher layer.)
func (t *SelfTrustRoots) MeetsFloor(level string) bool {
	rank := map[string]int{"green": 3, "yellow": 2, "red": 1}
	have := rank[govlevel.Normalize(level)]
	want := rank[govlevel.Normalize(t.GovernanceMinimum)]
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
