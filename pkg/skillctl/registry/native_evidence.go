package registry

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// NativeRevocationAuthority binds a HEAD signing key to explicit operator
// logical registry and tenant selection. The native wire does not sign a URI.
type NativeRevocationAuthority struct {
	registry     string
	tenant       *string
	key          ed25519.PublicKey
	historyID    string
	minimumEpoch int64
	maxAge       time.Duration
}

// NewNativeRevocationAuthority keeps HEAD authority separate from reviewer pins.
func NewNativeRevocationAuthority(logicalRegistry string, tenantScope *string, roots *NativeRootsSnapshot) (*NativeRevocationAuthority, error) {
	if roots == nil || roots.roots == nil || !agentText(logicalRegistry, 8192) || roots.roots.Registry != logicalRegistry {
		return nil, ErrNativeEvidenceInvalid
	}
	var tenant *string
	if tenantScope != nil {
		if !agentText(*tenantScope, 8192) {
			return nil, ErrNativeEvidenceInvalid
		}
		v := *tenantScope
		tenant = &v
	}
	descriptor := struct {
		Domain, Registry, Scope, Key string
		Tenant                       *string
	}{"m3c.native-history-authority/v1", logicalRegistry, "key-and-tenant", hex.EncodeToString(roots.roots.pub), tenant}
	raw, e := json.Marshal(descriptor)
	if e != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	return &NativeRevocationAuthority{registry: logicalRegistry, tenant: tenant, key: append(ed25519.PublicKey(nil), roots.roots.pub...), historyID: strings.TrimPrefix(agentDigest(raw), "sha256:"), minimumEpoch: 1, maxAge: 24 * time.Hour}, nil
}

// WithPolicy returns a restricted copy. Policy cannot exceed the mutation ceiling.
func (a *NativeRevocationAuthority) WithPolicy(minimumEpoch int64, maxAge time.Duration) (*NativeRevocationAuthority, error) {
	if a == nil || minimumEpoch < 1 || maxAge <= 0 || maxAge > 24*time.Hour {
		return nil, ErrNativeEvidenceInvalid
	}
	c := *a
	c.minimumEpoch = minimumEpoch
	c.maxAge = maxAge
	c.key = append(ed25519.PublicKey(nil), a.key...)
	if a.tenant != nil {
		v := *a.tenant
		c.tenant = &v
	}
	return &c, nil
}

// HistoryAuthorityID excludes current evidence and unrelated runtime/profile bytes.
func (a *NativeRevocationAuthority) HistoryAuthorityID() string {
	if a == nil {
		return ""
	}
	return a.historyID
}

// NativeEvidenceObservation is diagnostic data, never a mutation grant.
type NativeEvidenceObservation struct {
	EvidenceDigest string    `json:"evidence_digest"`
	Epoch          int64     `json:"epoch"`
	IssuedAt       time.Time `json:"issued_at"`
	RevokedCount   int       `json:"revoked_count"`
}

// NativeEvidenceSnapshot retains the validated bytes privately. It contains no
// enrolled history, journal lease or public approval boolean.
type NativeEvidenceSnapshot struct {
	raw         []byte
	observation NativeEvidenceObservation
}

// Observation returns scalar copied diagnostics without a mutation capability.
func (e *NativeEvidenceSnapshot) Observation() NativeEvidenceObservation {
	if e == nil {
		return NativeEvidenceObservation{}
	}
	return e.observation
}

// InspectNativeRevocationEvidence checks a native signed full set at the OS clock.
// Successful inspection is insufficient for any native Enterprise mutation.
func InspectNativeRevocationEvidence(raw []byte, authority *NativeRevocationAuthority) (*NativeEvidenceSnapshot, error) {
	return inspectNativeRevocationEvidence(raw, authority, time.Now().UTC())
}

func inspectNativeRevocationEvidence(raw []byte, a *NativeRevocationAuthority, now time.Time) (*NativeEvidenceSnapshot, error) {
	if a == nil || len(a.key) != ed25519.PublicKeySize || a.minimumEpoch < 1 || a.maxAge <= 0 || a.maxAge > 24*time.Hour || now.IsZero() {
		return nil, ErrNativeEvidenceInvalid
	}
	object, e := readAgentJSON(raw, 1<<20)
	if e != nil || len(object) != 3 || object["schema"] != "m3c.native-revocation-evidence/v1" {
		return nil, ErrNativeEvidenceInvalid
	}
	for _, k := range []string{"schema", "head", "revoked_digests"} {
		if _, ok := object[k]; !ok {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	head, ok := object["head"].(map[string]any)
	if !ok {
		return nil, ErrNativeEvidenceInvalid
	}
	keys := []string{"schema_version", "event_id", "occurred_at", "epoch", "issued_at", "revoked_set_root", "revoked_count", "emergency", "tenant_scope", "envelope_signature"}
	if len(head) != len(keys) {
		return nil, ErrNativeEvidenceInvalid
	}
	for _, k := range keys {
		if _, ok := head[k]; !ok {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	if head["schema_version"] != RevocationHeadSchema {
		return nil, ErrNativeEvidenceInvalid
	}
	for _, k := range []string{"event_id", "occurred_at", "issued_at", "revoked_set_root", "envelope_signature"} {
		s, ok := head[k].(string)
		if !ok || !agentText(s, 8192) {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	epoch, e := nativeInteger(head["epoch"])
	if e != nil || epoch < a.minimumEpoch {
		return nil, ErrNativeEvidenceInvalid
	}
	count, e := nativeInteger(head["revoked_count"])
	if e != nil || count < 0 || count > 8192 {
		return nil, ErrNativeEvidenceInvalid
	}
	issued, e := time.Parse(time.RFC3339Nano, head["issued_at"].(string))
	if e != nil || issued.IsZero() || issued.After(now) || now.Sub(issued) > a.maxAge {
		return nil, ErrNativeEvidenceInvalid
	}
	if _, e = time.Parse(time.RFC3339Nano, head["occurred_at"].(string)); e != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	if a.tenant == nil {
		if head["tenant_scope"] != nil {
			return nil, ErrNativeEvidenceInvalid
		}
	} else if head["tenant_scope"] != *a.tenant {
		return nil, ErrNativeEvidenceInvalid
	}
	set, e := nativeDigestArray(object["revoked_digests"], 8192)
	if e != nil || int64(len(set)) != count {
		return nil, ErrNativeEvidenceInvalid
	}
	emergency, e := nativeDigestArray(head["emergency"], 512)
	if e != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	members := make(map[string]bool, len(set))
	for _, d := range set {
		members[d] = true
	}
	for _, d := range emergency {
		if !members[d] {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	// This fixed signed schema has one array. The strict decoder preserves
	// array type but represents [] as a nil slice; restore [] rather than null
	// only after the array/type checks, keeping native canonical signature bytes.
	if len(emergency) == 0 {
		head["emergency"] = []any{}
	}
	remaining := 65536
	if encodedAgentSize(head, &remaining) != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	headRaw, e := json.Marshal(head)
	if e != nil || len(headRaw) > 65536 {
		return nil, ErrNativeEvidenceInvalid
	}
	if VerifyEnvelopeSignature(a.key, head) != nil || VerifyRevocationHeadSet(head, set) != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	// Copy only after all limits and native signature/set binding pass.
	return &NativeEvidenceSnapshot{raw: append([]byte(nil), raw...), observation: NativeEvidenceObservation{strings.TrimPrefix(agentDigest(raw), "sha256:"), epoch, issued.UTC(), len(set)}}, nil
}
func nativeInteger(v any) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, ErrNativeEvidenceInvalid
	}
	i, e := strconv.ParseInt(n.String(), 10, 64)
	if e != nil {
		return 0, ErrNativeEvidenceInvalid
	}
	return i, nil
}
func nativeDigestArray(v any, max int) ([]string, error) {
	values, ok := v.([]any)
	if !ok || len(values) > max {
		return nil, ErrNativeEvidenceInvalid
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		d, ok := value.(string)
		if !ok || len(d) != 71 || !strings.HasPrefix(d, "sha256:") || d != strings.ToLower(d) {
			return nil, ErrNativeEvidenceInvalid
		}
		if _, e := hex.DecodeString(d[7:]); e != nil || seen[d] {
			return nil, ErrNativeEvidenceInvalid
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}
