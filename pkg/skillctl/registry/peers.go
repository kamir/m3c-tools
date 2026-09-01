package registry

// SPEC-0359 D2 — peer discovery + trust pinning.
//
// A peer is 1:1 a NAMED SelfTrustRoots keyed by its registry locator: {name,
// locator, pinned ed25519 pubkey, fingerprint, governance floor}. Pulling from a
// peer verifies against THAT peer's pinned key — the pull gauntlet is already
// parameterized by *SelfTrustRoots, so a Peer.AsTrustRoots() adapter feeds it
// unchanged. The peer store is ~/.claude/skill-peers.yaml, mirroring the
// selftrustroots.go + verify.TrustRoots file mechanics (strict KnownFields YAML,
// atomic 0600 write, 0700 parent).
//
// Trust model (SPEC-0359 §9, confirmed 2026-08-31): fingerprint-REQUIRED, no
// trust-on-first-use. `peer add` takes the peer's pubkey AND its out-of-band
// fingerprint and refuses unless sha256(pubkey) matches the pin — the operator
// has independently confirmed the fingerprint over a trusted channel. The
// fingerprint (sha256:hex(sha256(rawPub))) is the same derivation as
// selfFingerprint / verify.authorFingerprint, so a fingerprint printed by any
// tool can be pinned here.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/govlevel"
	"gopkg.in/yaml.v3"
)

// Peer is one pinned registry. The GovernanceQuorum / GovernanceRootPubKeyB64
// fields are reserved for D3 (federation) and default to the D2 single-key model.
type Peer struct {
	Name              string `yaml:"name"`
	Locator           string `yaml:"locator"`
	PubKeyB64         string `yaml:"pubkey_b64"`
	Fingerprint       string `yaml:"fingerprint"`
	GovernanceMinimum string `yaml:"governance_minimum,omitempty"`

	// D3 (federation) — omitempty, unused in D2; documented for schema stability.
	GovernanceQuorum        int    `yaml:"governance_quorum,omitempty"`
	GovernanceRootPubKeyB64 string `yaml:"governance_root_pubkey_b64,omitempty"`
	CrossSignPath           string `yaml:"cross_sign_path,omitempty"`

	// D5(b): when true, this peer's SIGNED revoke events are unioned into the local
	// revoked set by `revoke feed --gossip` (a governance contributor). Default
	// false → the peer's feed is advisory only, bounding revoke-DoS.
	ContributesRevokes bool `yaml:"contributes_revokes,omitempty"`
}

// Peers is the loaded skill-peers.yaml.
type Peers struct {
	Peers []Peer `yaml:"peers"`
}

// DefaultPeersPath is the conventional peer-store location.
func DefaultPeersPath() string {
	return filepath.Join(userHome(), ".claude", "skill-peers.yaml")
}

// LoadPeers reads the peer store. path == "" → default. A missing file yields an
// empty store (not an error) so `peer add` bootstraps cleanly.
func LoadPeers(path string) (*Peers, error) {
	if path == "" {
		path = DefaultPeersPath()
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Peers{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("peers: open %s: %w", path, err)
	}
	var p Peers
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // strict: a typo'd field fails loudly rather than silently dropping a pin
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("peers: parse %s: %w", path, err)
	}
	// Validate each pin on load (fail closed on a tampered store).
	for i := range p.Peers {
		if _, err := p.Peers[i].AsTrustRoots(); err != nil {
			return nil, fmt.Errorf("peers: entry %q: %w", p.Peers[i].Name, err)
		}
	}
	return &p, nil
}

// Save writes the peer store atomically (0600 file, 0700 parent).
func (p *Peers) Save(path string) error {
	if path == "" {
		path = DefaultPeersPath()
	}
	sort.SliceStable(p.Peers, func(i, j int) bool { return p.Peers[i].Name < p.Peers[j].Name })
	data, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// FindPeerByLocator returns the pinned peer for a registry locator, if any.
func (p *Peers) FindPeerByLocator(locator string) (*Peer, bool) {
	for i := range p.Peers {
		if p.Peers[i].Locator == locator {
			return &p.Peers[i], true
		}
	}
	return nil, false
}

// FindPeerByName returns the pinned peer with the given name, if any.
func (p *Peers) FindPeerByName(name string) (*Peer, bool) {
	for i := range p.Peers {
		if p.Peers[i].Name == name {
			return &p.Peers[i], true
		}
	}
	return nil, false
}

// AddPeer validates and appends a peer. It REFUSES a peer whose pin does not
// verify (fingerprint-required, no TOFU) and a duplicate name/locator.
func (p *Peers) AddPeer(pe Peer) error {
	if strings.TrimSpace(pe.Name) == "" {
		return fmt.Errorf("peers: name required")
	}
	if strings.TrimSpace(pe.Locator) == "" {
		return fmt.Errorf("peers: locator required")
	}
	if strings.TrimSpace(pe.Fingerprint) == "" {
		return fmt.Errorf("peers: --pin <fingerprint> is required (no trust-on-first-use)")
	}
	if _, err := pe.AsTrustRoots(); err != nil {
		return err
	}
	if _, ok := p.FindPeerByName(pe.Name); ok {
		return fmt.Errorf("peers: a peer named %q already exists", pe.Name)
	}
	if _, ok := p.FindPeerByLocator(pe.Locator); ok {
		return fmt.Errorf("peers: locator %q is already pinned", pe.Locator)
	}
	p.Peers = append(p.Peers, pe)
	return nil
}

// RemovePeer deletes a peer by name; reports whether one was removed.
func (p *Peers) RemovePeer(name string) bool {
	for i := range p.Peers {
		if p.Peers[i].Name == name {
			p.Peers = append(p.Peers[:i], p.Peers[i+1:]...)
			return true
		}
	}
	return false
}

// AsTrustRoots builds the exact *SelfTrustRoots the pull gauntlet consumes from a
// pinned peer — the D2 adapter. It decodes the pubkey, recomputes and MATCHES the
// pinned fingerprint (fail closed on mismatch — no TOFU), and normalizes the
// floor. The resulting struct flows into PullBundles/PullBundlesFromBackend with
// zero downstream change; the peer's key becomes the verification anchor.
func (pe *Peer) AsTrustRoots() (*SelfTrustRoots, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pe.PubKeyB64))
	if err != nil {
		return nil, fmt.Errorf("pubkey_b64 not valid base64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey size %d, want %d", len(pubBytes), ed25519.PublicKeySize)
	}
	computed := selfFingerprint(pubBytes)
	if strings.TrimSpace(pe.Fingerprint) == "" {
		return nil, fmt.Errorf("fingerprint (pin) required, none stored")
	}
	if !strings.EqualFold(pe.Fingerprint, computed) {
		return nil, fmt.Errorf("fingerprint mismatch (pinned %s, key hashes to %s)", pe.Fingerprint, computed)
	}
	floor := pe.GovernanceMinimum
	if floor == "" {
		floor = "green"
	}
	norm, ok := govlevel.ValidFloor(floor)
	if !ok {
		return nil, fmt.Errorf("governance_minimum %q is not one of [green, yellow]", pe.GovernanceMinimum)
	}
	return &SelfTrustRoots{
		Registry:          pe.Locator,
		PubKeyB64:         pe.PubKeyB64,
		Fingerprint:       computed,
		GovernanceMinimum: norm,
		pub:               ed25519.PublicKey(pubBytes),
	}, nil
}
