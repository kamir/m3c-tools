package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillctl/govlevel"
)

const (
	agentEvidenceDir     = ".skillctl-evidence"
	agentRecordMagic     = "M3CAGT1\n"
	agentRecordSchema    = "m3c.agent-retained/v1"
	maxAgentHeader       = 8192
	maxAgentContext      = 1 << 20
	maxAgentNodes        = 16384
	maxAgentDepth        = 128
	maxAgentAttestations = 256
)

var (
	ErrAgentEvidenceRequired      = errors.New("agent signed evidence and explicit native trust roots required; pull again and reinstall the agent")
	ErrAgentEvidenceInvalid       = errors.New("agent retained evidence is invalid; pull again and reinstall the agent")
	ErrAgentPublicationIncomplete = errors.New("agent publication incomplete; active files may already have changed; inspect and reinstall")
)

type agentRecordHeader struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	BundleDigest  string `json:"bundle_digest"`
	ArchiveBytes  int64  `json:"archive_bytes"`
	ContextBytes  int64  `json:"context_bytes"`
	ContextSHA256 string `json:"context_sha256"`
}

type agentJSONBudget struct{ nodes, text int }

// Validate the complete caller tree before allocating its deep copy.
func (b *agentJSONBudget) validate(v any, depth int) error {
	if depth > maxAgentDepth || b.nodes >= maxAgentNodes {
		return ErrAgentEvidenceInvalid
	}
	b.nodes++
	switch x := v.(type) {
	case nil, bool:
		return nil
	case string:
		if !utf8.ValidString(x) || len(x) > maxAgentContext-b.text {
			return ErrAgentEvidenceInvalid
		}
		b.text += len(x)
		return nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return ErrAgentEvidenceInvalid
		}
		return nil
	case json.Number:
		if len(x) > 64 {
			return ErrAgentEvidenceInvalid
		}
		f, e := x.Float64()
		if e != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return ErrAgentEvidenceInvalid
		}
		return nil
	case map[string]any:
		if len(x) > maxAgentNodes-b.nodes {
			return ErrAgentEvidenceInvalid
		}
		for k, v := range x {
			if e := b.validate(k, depth+1); e != nil {
				return e
			}
			if e := b.validate(v, depth+1); e != nil {
				return e
			}
		}
		return nil
	case []any:
		if len(x) > maxAgentNodes-b.nodes {
			return ErrAgentEvidenceInvalid
		}
		for _, v := range x {
			if e := b.validate(v, depth+1); e != nil {
				return e
			}
		}
		return nil
	default:
		return ErrAgentEvidenceInvalid
	}
}

// Only primitive JSON data is copied. In particular no caller Marshaler runs.
func (b *agentJSONBudget) clone(v any, depth int) (any, error) {
	if depth > maxAgentDepth || b.nodes >= maxAgentNodes {
		return nil, ErrAgentEvidenceInvalid
	}
	b.nodes++
	switch x := v.(type) {
	case nil, bool:
		return x, nil
	case string:
		if !utf8.ValidString(x) || len(x) > maxAgentContext-b.text {
			return nil, ErrAgentEvidenceInvalid
		}
		b.text += len(x)
		return x, nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, ErrAgentEvidenceInvalid
		}
		return x, nil
	case json.Number:
		if len(x) > 64 {
			return nil, ErrAgentEvidenceInvalid
		}
		f, e := x.Float64()
		if e != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, ErrAgentEvidenceInvalid
		}
		return x, nil
	case map[string]any:
		if len(x) > maxAgentNodes-b.nodes {
			return nil, ErrAgentEvidenceInvalid
		}
		out := make(map[string]any, len(x))
		for k, v := range x {
			if _, err := b.clone(k, depth+1); err != nil {
				return nil, err
			}
			c, err := b.clone(v, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case []any:
		if len(x) > maxAgentNodes-b.nodes {
			return nil, ErrAgentEvidenceInvalid
		}
		out := make([]any, len(x))
		for i, v := range x {
			c, e := b.clone(v, depth+1)
			if e != nil {
				return nil, e
			}
			out[i] = c
		}
		return out, nil
	default:
		return nil, ErrAgentEvidenceInvalid
	}
}

// encodedAgentSize counts JSON escaping without building a serialized buffer.
func encodedAgentSize(v any, left *int) error {
	charge := func(n int) error {
		if n < 0 || n > *left {
			return ErrAgentEvidenceInvalid
		}
		*left -= n
		return nil
	}
	switch x := v.(type) {
	case nil:
		return charge(4)
	case bool:
		if x {
			return charge(4)
		}
		return charge(5)
	case float64, json.Number:
		return charge(64) // conservative finite number encoding bound
	case string:
		if err := charge(2); err != nil {
			return err
		}
		for _, r := range x {
			n := len(string(r))
			if r < ' ' || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029' {
				n = 6
			} else if r == '"' || r == '\\' {
				n = 2
			}
			if err := charge(n); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if err := charge(2 + len(x)); err != nil {
			return err
		}
		for _, v := range x {
			if err := encodedAgentSize(v, left); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if err := charge(2 + 2*len(x)); err != nil {
			return err
		}
		for k, v := range x {
			if err := encodedAgentSize(k, left); err != nil {
				return err
			}
			if err := encodedAgentSize(v, left); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrAgentEvidenceInvalid
	}
}

func snapshotAgentContext(c *AttestationContext) (*AttestationContext, []byte, error) {
	if c == nil || c.AdmitEvent == nil || c.GovernanceAttestation == nil {
		return nil, nil, ErrAgentEvidenceRequired
	}
	if len(c.GovernanceAttestations) > maxAgentAttestations {
		return nil, nil, ErrAgentEvidenceInvalid
	}
	b := agentJSONBudget{}
	object := map[string]any{"admit_event": c.AdmitEvent, "governance_attestation": c.GovernanceAttestation}
	list := make([]any, len(c.GovernanceAttestations))
	for i, v := range c.GovernanceAttestations {
		list[i] = v
	}
	if len(list) > 0 {
		object["governance_attestations"] = list
	}
	if err := b.validate(object, 1); err != nil {
		return nil, nil, err
	}
	left := maxAgentContext
	if encodedAgentSize(object, &left) != nil {
		return nil, nil, ErrAgentEvidenceInvalid
	}
	b = agentJSONBudget{}
	copy, err := b.clone(object, 1)
	if err != nil {
		return nil, nil, err
	}

	raw, err := json.Marshal(copy)
	if err != nil || len(raw) > maxAgentContext {
		return nil, nil, ErrAgentEvidenceInvalid
	}
	var result AttestationContext
	if json.Unmarshal(raw, &result) != nil {
		return nil, nil, ErrAgentEvidenceInvalid
	}
	return &result, raw, nil
}

func snapshotAgentRoots(r *SelfTrustRoots) (*SelfTrustRoots, error) {
	if r == nil {
		return nil, ErrAgentEvidenceRequired
	}
	if len(r.Signers) > 256 || r.GovernanceQuorum < 0 || r.GovernanceQuorum > 256 {
		return nil, ErrAgentEvidenceInvalid
	}
	total := 0
	text := func(s string, max int) bool {
		if len(s) > max || !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) || len(s) > 65536-total {
			return false
		}
		total += len(s)
		return true
	}
	for _, s := range []string{r.Registry, r.PubKeyB64, r.Fingerprint, r.GovernanceMinimum, r.GovernanceRootPubKeyB64} {
		if !text(s, 8192) {
			return nil, ErrAgentEvidenceInvalid
		}
	}
	if !text(r.Path, 4096) || !text(r.CrossSignPath, 4096) || strings.TrimSpace(r.Registry) == "" || len(r.pub) != ed25519.PublicKeySize {
		return nil, ErrAgentEvidenceInvalid
	}
	if r.PubKeyB64 != "" {
		declared, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.PubKeyB64))
		if err != nil || !bytes.Equal(declared, r.pub) {
			return nil, ErrAgentEvidenceInvalid
		}
	}
	if r.Fingerprint != "" && !strings.EqualFold(r.Fingerprint, selfFingerprint(r.pub)) {
		return nil, ErrAgentEvidenceInvalid
	}
	floor, ok := govlevel.ValidFloor(r.GovernanceMinimum)
	if !ok {
		return nil, ErrAgentEvidenceInvalid
	}
	for _, s := range r.Signers {
		if !text(s.ReviewerID, 8192) || !text(s.PubKeyB64, 8192) || len(s.pub) != 32 {
			return nil, ErrAgentEvidenceInvalid
		}
	}
	result := *r
	result.GovernanceMinimum = floor
	result.pub = append(ed25519.PublicKey(nil), r.pub...)
	result.Signers = make([]Signer, len(r.Signers))
	seen := map[string]bool{}
	for i, s := range r.Signers {

		if s.PubKeyB64 != "" {
			p, e := base64.StdEncoding.DecodeString(strings.TrimSpace(s.PubKeyB64))
			if e != nil || !bytes.Equal(p, s.pub) {
				return nil, ErrAgentEvidenceInvalid
			}
		}
		result.Signers[i] = s
		result.Signers[i].pub = append(ed25519.PublicKey(nil), s.pub...)
		seen[string(s.pub)] = true
	}
	available := len(seen)
	if available == 0 {
		available = 1
	}
	if r.quorum() > available {
		return nil, ErrAgentEvidenceInvalid
	}
	return &result, nil
}

func verifyAgentContext(r *SelfTrustRoots, c *AttestationContext, digest, name, version string, now time.Time) error {
	if now.IsZero() || c == nil {
		return ErrAgentEvidenceInvalid
	}
	if VerifyEnvelopeSignature(r.pub, c.AdmitEvent) != nil || verifyBundleSignatures(c.AdmitEvent, r.pub, digest) != nil {
		return ErrAgentEvidenceInvalid
	}
	for key, want := range map[string]string{"name": name, "version": version} {
		if v, exists := c.AdmitEvent[key]; exists && v != want {
			return ErrAgentEvidenceInvalid
		}
	}
	if v, exists := c.AdmitEvent["registry"]; exists && v != r.Registry {
		return ErrAgentEvidenceInvalid
	}
	if c.AdmitEvent["bundle_digest"] != digest {
		return ErrAgentEvidenceInvalid
	}
	roles := map[string]bool{}
	sigs, ok := c.AdmitEvent["signatures"].([]any)
	if !ok {
		return ErrAgentEvidenceInvalid
	}
	for _, sig := range sigs {
		m, ok := sig.(map[string]any)
		if !ok {
			return ErrAgentEvidenceInvalid
		}
		role, _ := m["role"].(string)
		if role != "author" && role != "registry" {
			return ErrAgentEvidenceInvalid
		}
		roles[role] = true
	}
	if !roles["author"] || !roles["registry"] {
		return ErrAgentEvidenceInvalid
	}
	acc := NewAttestAccumulator(r, now)
	events := make([]map[string]any, 0, len(c.GovernanceAttestations)+1)
	events = append(events, c.GovernanceAttestation)
	events = append(events, c.GovernanceAttestations...)
	for _, event := range events {
		if event == nil || event["bundle_digest"] != digest || verifyGovernanceSigner(r.pub, r.signerSet(), event) != nil {
			return ErrAgentEvidenceInvalid
		}
		reviewer, rok := event["reviewer_id"].(string)
		level, lok := event["governance_level"].(string)
		occurred, tok := event["occurred_at"].(string)
		normalized := govlevel.Normalize(level)
		if !rok || !agentText(reviewer, 8192) || !lok || (normalized != govlevel.Green && normalized != govlevel.Yellow && normalized != govlevel.Red) || !tok {
			return ErrAgentEvidenceInvalid
		}
		if _, e := time.Parse(time.RFC3339, occurred); e != nil {
			return ErrAgentEvidenceInvalid
		}
		if value, exists := event["expires_at"]; exists {
			expiry, ok := value.(string)
			if !ok {
				return ErrAgentEvidenceInvalid
			}
			if _, e := time.Parse(time.RFC3339, expiry); e != nil {
				return ErrAgentEvidenceInvalid
			}
		}
		acc.OfferAttest(event)
	}
	levels := make([]string, 0, len(acc.Qualifying(digest)))
	for _, rec := range acc.Qualifying(digest) {
		levels = append(levels, rec.level)
	}
	if !r.MeetsQuorum(levels) {
		return ErrAgentEvidenceInvalid
	}
	return nil
}

func readAgentJSON(raw []byte, max int) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return nil, ErrAgentEvidenceInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 128 || nodes >= maxAgentNodes {
			return nil, ErrAgentEvidenceInvalid
		}
		nodes++
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return t, nil
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok {
					return nil, ErrAgentEvidenceInvalid
				}
				nodes++
				if _, exists := m[s]; exists {
					return nil, ErrAgentEvidenceInvalid
				}
				v, e := value(depth + 1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			_, e = d.Token()
			return m, e
		case '[':
			var a []any
			for d.More() {
				v, e := value(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e = d.Token()
			return a, e
		}
		return nil, ErrAgentEvidenceInvalid
	}
	v, err := value(1)
	if err != nil {
		return nil, ErrAgentEvidenceInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, ErrAgentEvidenceInvalid
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrAgentEvidenceInvalid
	}
	return m, nil
}

func agentDigest(raw []byte) string {
	s := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(s[:])
}
func agentPublicationFailure(cause error) error {
	return errors.Join(ErrAgentPublicationIncomplete, cause)
}
func agentText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}
func agentRecordName(name string) string { return name + ".record" }
func agentEvidenceDiagnostic(err error) error {
	if errors.Is(err, ErrAgentEvidenceRequired) {
		return ErrAgentEvidenceRequired
	}
	return fmt.Errorf("agent evidence refused; pull again and reinstall the agent: %w", err)
}

func validAgentName(name string) bool {
	return agentText(name, 248) && !strings.HasPrefix(name, ".") && sanitizeBundleName(name) == nil
}
