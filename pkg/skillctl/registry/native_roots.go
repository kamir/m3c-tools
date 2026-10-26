package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ErrNativeEvidenceInvalid classifies bounded native profile/evidence failures.
var ErrNativeEvidenceInvalid = errors.New("native authority or revocation evidence is invalid")

// ErrNativeUnsupported excludes authority forms that have no immutable adapter.
var ErrNativeUnsupported = errors.New("native authority mapping is unsupported")

// NativeRootsSnapshot privately retains direct pinned native role authority.
// Cross-signed membership is unsupported; no filesystem paths are resolved.
type NativeRootsSnapshot struct{ roots *SelfTrustRoots }

// ParseNativeRootsSnapshot parses one bounded native YAML document from the same
// bytes whose pin the profile checked. Legacy path loaders are not invoked.
func ParseNativeRootsSnapshot(raw []byte) (*NativeRootsSnapshot, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return nil, ErrNativeEvidenceInvalid
	}
	var node yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(&node) != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	var extra yaml.Node
	if dec.Decode(&extra) != io.EOF {
		return nil, ErrNativeEvidenceInvalid
	}
	nodes := 0
	if nativeYAMLNode(&node, 0, &nodes) != nil || len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return nil, ErrNativeEvidenceInvalid
	}
	quorumPresent := false
	for i := 0; i < len(node.Content[0].Content); i += 2 {
		key := node.Content[0].Content[i].Value
		if strings.EqualFold(key, "cross_sign_path") || strings.EqualFold(key, "governance_root_pubkey_b64") {
			return nil, ErrNativeUnsupported
		}
	}
	for i := 0; i < len(node.Content[0].Content); i += 2 {
		if node.Content[0].Content[i].Value == "signers" && (node.Content[0].Content[i+1].Kind != yaml.SequenceNode || len(node.Content[0].Content[i+1].Content) > 256) {
			return nil, ErrNativeEvidenceInvalid
		}
		if node.Content[0].Content[i].Value == "governance_quorum" {
			quorumPresent = true
			if node.Content[0].Content[i+1].Tag != "!!int" {
				return nil, ErrNativeEvidenceInvalid
			}
		}
	}
	var root SelfTrustRoots
	typed := yaml.NewDecoder(bytes.NewReader(raw))
	typed.KnownFields(true)
	if typed.Decode(&root) != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	if quorumPresent && (root.GovernanceQuorum < 1 || root.GovernanceQuorum > 256) {
		return nil, ErrNativeEvidenceInvalid
	}
	if root.CrossSignPath != "" || root.GovernanceRootPubKeyB64 != "" {
		return nil, ErrNativeUnsupported
	}
	if !agentText(root.Registry, 8192) || root.PubKeyB64 == "" {
		return nil, ErrNativeEvidenceInvalid
	}
	if len(root.Signers) > 256 {
		return nil, ErrNativeEvidenceInvalid
	}
	if root.GovernanceQuorum == 0 {
		root.GovernanceQuorum = 1
	}
	if root.GovernanceMinimum == "" {
		root.GovernanceMinimum = "green"
	}
	// Bound every textual field before decoding keys or allocating private copies.
	total := len(root.Registry) + len(root.PubKeyB64) + len(root.Fingerprint) + len(root.GovernanceMinimum)
	for _, s := range []string{root.PubKeyB64, root.Fingerprint, root.GovernanceMinimum} {
		if len(s) > 8192 {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	for _, signer := range root.Signers {
		if !agentText(signer.ReviewerID, 8192) || !agentText(signer.PubKeyB64, 8192) || total > 65536-len(signer.ReviewerID)-len(signer.PubKeyB64) {
			return nil, ErrNativeEvidenceInvalid
		}
		total += len(signer.ReviewerID) + len(signer.PubKeyB64)
	}
	if total > 65536 {
		return nil, ErrNativeEvidenceInvalid
	}
	pub, e := base64.StdEncoding.DecodeString(strings.TrimSpace(root.PubKeyB64))
	if e != nil || len(pub) != ed25519.PublicKeySize {
		return nil, ErrNativeEvidenceInvalid
	}
	root.pub = ed25519.PublicKey(pub)
	for i := range root.Signers {
		key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(root.Signers[i].PubKeyB64))
		if e != nil || len(key) != ed25519.PublicKeySize {
			return nil, ErrNativeEvidenceInvalid
		}
		root.Signers[i].pub = ed25519.PublicKey(key)
	}
	copied, e := snapshotAgentRoots(&root)
	if e != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	// Duplicate signer keys or IDs cannot manufacture a larger reviewer set.
	seenKeys, seenIDs := map[string]bool{}, map[string]bool{}
	for _, s := range copied.Signers {
		key := string(s.pub)
		if seenKeys[key] || seenIDs[s.ReviewerID] {
			return nil, ErrNativeEvidenceInvalid
		}
		seenKeys[key] = true
		seenIDs[s.ReviewerID] = true
	}
	return &NativeRootsSnapshot{roots: copied}, nil
}

func nativeYAMLNode(n *yaml.Node, depth int, nodes *int) error {
	*nodes++
	if n.Kind == yaml.ScalarNode && len(n.Value) > 8192 {
		return ErrNativeEvidenceInvalid
	}
	if depth > 128 || *nodes > 16384 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" {
		return ErrNativeEvidenceInvalid
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return ErrNativeEvidenceInvalid
			}
			fold := strings.ToLower(k.Value)
			if seen[fold] {
				return ErrNativeEvidenceInvalid
			}
			seen[fold] = true
		}
	}
	for _, child := range n.Content {
		if e := nativeYAMLNode(child, depth+1, nodes); e != nil {
			return e
		}
	}
	return nil
}

// Roots returns a deep copy; changing legacy mutable keys does not change policy.
func (s *NativeRootsSnapshot) Roots() *SelfTrustRoots {
	if s == nil || s.roots == nil {
		return nil
	}
	r := *s.roots
	r.pub = append(ed25519.PublicKey(nil), s.roots.pub...)
	r.Signers = append([]Signer(nil), s.roots.Signers...)
	for i := range r.Signers {
		r.Signers[i].pub = append(ed25519.PublicKey(nil), s.roots.Signers[i].pub...)
	}
	return &r
}
