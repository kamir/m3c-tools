package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// ErrNativeLiveSourceIO reports transport or selected external credential I/O.
// Error text never includes a server response, URL or credential value.
var ErrNativeLiveSourceIO = errors.New("native live agent source unavailable")

const (
	nativeLiveResponseMax = 32 << 20
	nativeLiveArchiveMax  = 16 << 20
	nativeLiveContextMax  = 1 << 20
	nativeLiveWorkMax     = 512 << 20
	nativeLiveTokenMax    = 32768
)

type nativeLiveSourceError struct{ cause error }

func (e *nativeLiveSourceError) Error() string { return ErrNativeLiveSourceIO.Error() }
func (e *nativeLiveSourceError) Unwrap() []error {
	return []error{ErrNativeLiveSourceIO, e.cause}
}
func nativeLiveIO(err error) error { return &nativeLiveSourceError{cause: err} }

// NativeLiveAgentSourceOptions contains only explicitly selected metadata.
// external-env selects exactly one fixed ER1 environment variable; constructors
// never read it. CAPEM belongs only to this carrier, not its revocation source.
type NativeLiveAgentSourceOptions struct {
	BaseURL, ContextID, AuthMode, AuthFamily, AuthOrigin, TLSMode string
	CAPEM                                                         []byte
}

// NativeLiveAgentCandidate is untrusted retained input, not installation authority.
// No cache/staging path is created. The native session still authenticates it.
type NativeLiveAgentCandidate struct {
	Archive   []byte
	Bundle    *StagedBundle
	workBytes int64
}

// NativeLiveAgentSource owns a frozen endpoint/TLS/auth selection. Private seams
// are observations/fault injection for package tests, never caller capabilities.
type NativeLiveAgentSource struct {
	endpoint, contextID, authMode, family string
	binding                               string
	roots                                 *x509.CertPool
	dialContext                           func(context.Context, string, string) (net.Conn, error)
	closeBody                             func(io.ReadCloser) error
	readEnv                               func(string) (string, bool)
	responseMax                           int // test-only lower ceiling; never above the production cap
}

// NewNativeLiveAgentSource validates metadata and retains TLS roots without
// credential lookup, network, staging, or a grant to mutate.
func NewNativeLiveAgentSource(o NativeLiveAgentSourceOptions) (*NativeLiveAgentSource, error) {
	// Public SDK callers need the same pre-allocation bounds as profile callers.
	// Finish this pass before any URL parse, PEM parse/copy or consent Marshal.
	if len(o.BaseURL) > 8192 || len(o.ContextID) > 8192 || len(o.AuthOrigin) > 8192 || len(o.AuthMode) > 64 || len(o.AuthFamily) > 64 || len(o.TLSMode) > 64 || len(o.CAPEM) > nativeEvidenceCAMax {
		return nil, ErrNativeEvidenceInvalid
	}
	for _, text := range []string{o.BaseURL, o.ContextID, o.AuthOrigin, o.AuthMode, o.AuthFamily, o.TLSMode} {
		if !utf8.ValidString(text) {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	if !agentText(o.ContextID, 8192) || strings.ContainsAny(o.ContextID, "/\\%?#") || o.ContextID == "." || o.ContextID == ".." || strings.ContainsFunc(o.ContextID, unicode.IsSpace) {
		return nil, ErrNativeEvidenceInvalid
	}
	base, err := httpsafe.ParseAPIBase(o.BaseURL, false)
	if err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	if _, err = httpsafe.NewGETBoundary(base.URL, false, 1); err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	endpoint := strings.TrimRight(base.URL, "/") + "/memory/" + url.PathEscape(o.ContextID)
	if _, err = httpsafe.NewGETBoundary(endpoint, false, 1); err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	switch o.AuthMode {
	case "none":
		if o.AuthFamily != "" || o.AuthOrigin != "" {
			return nil, ErrNativeEvidenceInvalid
		}
	case "external-env":
		origin, e := httpsafe.ParseAPIBase(o.AuthOrigin, false)
		if e != nil || o.AuthOrigin != origin.Origin.String() || origin.Origin != base.Origin || (o.AuthFamily != "api-key" && o.AuthFamily != "bearer") {
			return nil, ErrNativeEvidenceInvalid
		}
	default:
		return nil, ErrNativeEvidenceInvalid
	}
	var roots *x509.CertPool
	switch o.TLSMode {
	case "system":
		if len(o.CAPEM) != 0 {
			return nil, ErrNativeEvidenceInvalid
		}
	case "pinned-pem":
		// Reuse the strict bounded CA inventory parser; its private pool is never
		// exposed or combined with another source's roots.
		selected, e := NewNativePinnedEvidenceSource(endpoint, o.CAPEM)
		if e != nil {
			return nil, ErrNativeEvidenceInvalid
		}
		roots = selected.roots
	default:
		return nil, ErrNativeEvidenceInvalid
	}
	caSHA := ""
	if o.TLSMode == "pinned-pem" {
		sum := sha256.Sum256(o.CAPEM)
		caSHA = hex.EncodeToString(sum[:])
	}
	metadata, err := json.Marshal(struct {
		Domain, Base, Context, AuthMode, Family, Origin, TLSMode, CASHA string
	}{"m3c.native-live-source/v1", strings.TrimRight(base.URL, "/"), o.ContextID, o.AuthMode, o.AuthFamily, o.AuthOrigin, o.TLSMode, caSHA})
	if err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	binding := sha256.Sum256(metadata)
	return &NativeLiveAgentSource{endpoint: endpoint + "?limit=500&range=year", contextID: o.ContextID, authMode: o.AuthMode, family: o.AuthFamily, roots: roots, binding: hex.EncodeToString(binding[:])}, nil
}

func (s *NativeLiveAgentSource) bindingID() string {
	if s == nil {
		return ""
	}
	return s.binding
}

type nativeLiveWork struct {
	bytes  int64
	tokens int
}

func (b *nativeLiveWork) charge(n int64) error {
	if n < 0 || n > nativeLiveWorkMax-b.bytes {
		return ErrNativeEvidenceInvalid
	}
	b.bytes += n
	return nil
}

// Fetch requires the concrete existing native lease before even reading a
// selected external value. The facade must not hold session.mu when calling it.
func (s *NativeLiveAgentSource) Fetch(ctx context.Context, session *NativeInstallSession) (candidate *NativeLiveAgentCandidate, resultErr error) {
	if s == nil || s.endpoint == "" || session == nil || ctx == nil {
		return nil, ErrNativeSessionUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !session.mu.TryLock() {
		return nil, ErrNativeSessionUnavailable
	}
	defer session.mu.Unlock()
	if err := session.usable(ctx); err != nil {
		return nil, nativeSessionDiagnostic(err)
	}
	defer func() {
		if resultErr != nil {
			session.poisoned = true
			candidate = nil
		}
	}()
	if err := session.lease.recheck(ctx, session.rootDigest); err != nil {
		session.poisoned = true
		return nil, nativeSessionDiagnostic(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nativeLiveIO(err)
	}
	responseMax := nativeLiveResponseMax
	if s.responseMax != 0 {
		if s.responseMax < 1 || s.responseMax > nativeLiveResponseMax {
			return nil, ErrNativeEvidenceInvalid
		}
		responseMax = s.responseMax
	}
	secret := ""
	if s.authMode == "external-env" {
		name := "ER1_API_KEY"
		if s.family == "bearer" {
			name = "ER1_DEVICE_TOKEN"
		}
		read := s.readEnv
		if read == nil {
			read = os.LookupEnv
		}
		var ok bool
		secret, ok = read(name)
		if !ok || len(secret) == 0 || len(secret) > 8192 || strings.TrimSpace(secret) != secret || strings.ContainsFunc(secret, unicode.IsControl) || !utf8.ValidString(secret) {
			return nil, nativeLiveIO(ErrNativeLiveSourceIO)
		}
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if s.roots != nil {
		tlsConfig.RootCAs = s.roots.Clone()
	}
	dial := s.dialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, Protocols: protocols}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return nil, nativeLiveIO(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Context-ID", s.contextID)
	if s.authMode == "external-env" {
		if s.family == "bearer" {
			req.Header.Set("Authorization", "Bearer "+secret)
		} else {
			req.Header.Set("X-API-KEY", secret)
		}
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, nativeLiveIO(err)
	}
	defer func() {
		closeBody := s.closeBody
		if closeBody == nil {
			closeBody = func(body io.ReadCloser) error { return body.Close() }
		}
		if e := errors.Join(closeBody(resp.Body), ctx.Err()); e != nil {
			resultErr = errors.Join(resultErr, nativeLiveIO(e))
		}
		if resultErr != nil {
			candidate = nil
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, nativeLiveIO(ErrNativeLiveSourceIO)
	}
	media, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	encoding := resp.Header.Get("Content-Encoding")
	if len(resp.Header.Values("Content-Type")) != 1 || len(resp.Header.Values("Content-Encoding")) > 1 || err != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) || (encoding != "" && !strings.EqualFold(encoding, "identity")) || resp.ContentLength > int64(responseMax) {
		return nil, ErrNativeEvidenceInvalid
	}
	budget := &nativeLiveWork{}
	// Reserve the cap and ReadAll growth/copy overhead before reading any body.
	if err = budget.charge(4 * (int64(responseMax) + 1)); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(responseMax)+1))
	if err != nil {
		return nil, nativeLiveIO(err)
	}
	if len(raw) == 0 || len(raw) > responseMax {
		return nil, ErrNativeEvidenceInvalid
	}
	if err = ctx.Err(); err != nil {
		return nil, nativeLiveIO(err)
	}
	return nativeLiveParse(raw, secret, session, budget)
}

// nativeLiveJSON validates the entire wire tree before its map materialization.
// One operation-wide budget charges repeated parses, with no refunds.
func nativeLiveJSON(raw []byte, max int, secret string, b *nativeLiveWork) (any, error) {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) || (secret != "" && bytes.Contains(raw, []byte(secret))) {
		return nil, ErrNativeEvidenceInvalid
	}
	if err := b.charge(2 * int64(len(raw))); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := nativeLiveJSONValue(d, 0, secret, b); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrNativeEvidenceInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	return value, nil
}

func nativeLiveJSONValue(d *json.Decoder, depth int, secret string, b *nativeLiveWork) error {
	if depth > 128 || b.tokens >= nativeLiveTokenMax || b.charge(128) != nil {
		return ErrNativeEvidenceInvalid
	}
	b.tokens++
	token, err := d.Token()
	if err != nil {
		return ErrNativeEvidenceInvalid
	}
	if text, ok := token.(string); ok {
		if (secret != "" && strings.Contains(text, secret)) || b.charge(2*int64(len(text))) != nil {
			return ErrNativeEvidenceInvalid
		}
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] || !nativeLiveCanonicalKey(name) || b.tokens >= nativeLiveTokenMax || b.charge(128+2*int64(len(name))) != nil || (secret != "" && strings.Contains(name, secret)) {
				return ErrNativeEvidenceInvalid
			}
			b.tokens++
			seen[name] = true
			if err = nativeLiveJSONValue(d, depth+1, secret, b); err != nil {
				return err
			}
		}
		if err = nativeLiveJSONEnd(d, json.Delim('}'), b); err != nil {
			return ErrNativeEvidenceInvalid
		}
	case json.Delim('['):
		for d.More() {
			if err = nativeLiveJSONValue(d, depth+1, secret, b); err != nil {
				return err
			}
		}
		if err = nativeLiveJSONEnd(d, json.Delim(']'), b); err != nil {
			return ErrNativeEvidenceInvalid
		}
	case json.Delim('}'), json.Delim(']'):
		return ErrNativeEvidenceInvalid
	}
	return nil
}

func nativeLiveJSONEnd(d *json.Decoder, want json.Delim, b *nativeLiveWork) error {
	if b.tokens >= nativeLiveTokenMax || b.charge(128) != nil {
		return ErrNativeEvidenceInvalid
	}
	b.tokens++
	end, err := d.Token()
	if err != nil || end != want {
		return ErrNativeEvidenceInvalid
	}
	return nil
}

func nativeLiveCanonicalKey(key string) bool {
	fold := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	for _, canonical := range []string{"items", "transcript", "doc_id", "bundle_digest", "tenant_scope", "schema_version", "envelope_signature", "signatures", "signature_b64", "pubkey_fingerprint", "identity_id", "role", "registry", "reviewer_id", "governance_level", "occurred_at", "expires_at", "admitted_by_identity", "admitted_at", "reason_code", "revoked_by", "blob_uri", "name", "version"} {
		if fold == strings.ReplaceAll(canonical, "_", "") && key != canonical {
			return false
		}
	}
	return true
}

func nativeLiveFence(body, label string) (string, error) {
	marker := "```" + label + "\n"
	if strings.Count(body, "```"+label) != 1 || strings.Count(body, marker) != 1 {
		return "", ErrNativeEvidenceInvalid
	}
	_, after, _ := strings.Cut(body, marker)
	content, rest, ok := strings.Cut(after, "\n```")
	if !ok || strings.HasPrefix(rest, "`") || (rest != "" && !strings.HasPrefix(rest, "\n")) || strings.Contains(content, "```") {
		return "", ErrNativeEvidenceInvalid
	}
	return content, nil
}

func nativeLiveItems(value any) ([]any, error) {
	if object, ok := value.(map[string]any); ok {
		// No pagination/partial-result metadata is silently ignored. The live
		// subset supports one complete page in exactly this wrapper or an array.
		if len(object) != 1 {
			return nil, ErrNativeEvidenceInvalid
		}
		value = object["items"]
	}
	items, ok := value.([]any)
	if !ok || len(items) >= 500 {
		return nil, ErrNativeEvidenceInvalid
	}
	return items, nil
}

func nativeLiveBody(item map[string]any) (string, string, error) {
	for _, key := range []string{"transcript_text", "body", "content", "text", "data", "fields"} {
		if _, exists := item[key]; exists {
			return "", "", ErrNativeEvidenceInvalid
		}
	}
	body, ok := item["transcript"].(string)
	if !ok {
		return "", "", ErrNativeEvidenceInvalid
	}
	id, hasID := item["id"]
	doc, hasDoc := item["doc_id"]
	if hasID {
		if _, ok := id.(string); !ok {
			return "", "", ErrNativeEvidenceInvalid
		}
	}
	if hasDoc {
		if _, ok := doc.(string); !ok {
			return "", "", ErrNativeEvidenceInvalid
		}
	}
	if hasID && hasDoc && id.(string) != doc.(string) {
		return "", "", ErrNativeEvidenceInvalid
	}
	if hasDoc {
		id = doc
	}
	text, ok := id.(string)
	if !ok || !agentText(text, 8192) {
		return "", "", ErrNativeEvidenceInvalid
	}
	return body, text, nil
}

func nativeLiveParse(raw []byte, secret string, s *NativeInstallSession, budget *nativeLiveWork) (*NativeLiveAgentCandidate, error) {
	value, err := nativeLiveJSON(raw, nativeLiveResponseMax, secret, budget)
	if err != nil {
		return nil, err
	}
	items, err := nativeLiveItems(value)
	if err != nil {
		return nil, err
	}
	var admit map[string]any
	var archiveBody, sourceID string
	var attestations []map[string]any
	for _, value := range items {
		item, ok := value.(map[string]any)
		if !ok {
			return nil, ErrNativeEvidenceInvalid
		}
		body, id, err := nativeLiveBody(item)
		if err != nil {
			return nil, err
		}
		if !strings.Contains(body, "```json") {
			continue // unrelated ordinary ER1 memory, never a trust assertion
		}
		eventRaw, err := nativeLiveFence(body, "json")
		if err != nil {
			return nil, err
		}
		if len(eventRaw) > nativeLiveContextMax || budget.charge(int64(len(eventRaw))) != nil {
			return nil, ErrNativeEvidenceInvalid
		}
		eventValue, err := nativeLiveJSON([]byte(eventRaw), nativeLiveContextMax, secret, budget)
		if err != nil {
			return nil, err
		}
		event, ok := eventValue.(map[string]any)
		if !ok {
			return nil, ErrNativeEvidenceInvalid
		}
		digest, ok := event["bundle_digest"].(string)
		if !ok || digest != s.rootDigest {
			continue
		}
		if err = nativeLiveTenant(event, s); err != nil {
			return nil, err
		}
		admitted := false
		for _, key := range []string{"admitted_by_identity", "admitted_at", "signatures", "author_intent", "blob_uri"} {
			if _, exists := event[key]; exists {
				admitted = true
			}
		}
		_, reviewer := event["reviewer_id"]
		_, governance := event["governance_level"]
		_, revoked := event["revoked_by"]
		_, reason := event["reason_code"]
		kinds := 0
		for _, yes := range []bool{admitted, reviewer || governance, revoked || reason} {
			if yes {
				kinds++
			}
		}
		if kinds != 1 {
			return nil, ErrNativeEvidenceInvalid
		}
		if revoked || reason {
			return nil, ErrNativeEvidenceInvalid
		}
		if admitted {
			if admit != nil || event["blob_uri"] != nil {
				return nil, ErrNativeEvidenceInvalid
			}
			archiveBody, err = nativeLiveFence(body, "skb-base64")
			if err != nil {
				return nil, err
			}
			admit, sourceID = event, id
			continue
		}
		level, levelOK := event["governance_level"].(string)
		if !reviewer || !governance || !levelOK || strings.EqualFold(strings.TrimSpace(level), "red") || len(attestations) >= 256 || strings.Contains(body, "```skb-base64") {
			return nil, ErrNativeEvidenceInvalid
		}
		if err = budget.charge(128); err != nil {
			return nil, err
		}
		attestations = append(attestations, event)
	}
	if admit == nil || len(attestations) == 0 {
		return nil, ErrNativeEvidenceInvalid
	}
	name, nameOK := admit["name"].(string)
	version, versionOK := admit["version"].(string)
	identity, identityOK := admit["admitted_by_identity"].(string)
	if !nameOK || !validAgentName(name) || !versionOK || !agentText(version, 256) || !identityOK || !agentText(identity, 8192) {
		return nil, ErrNativeEvidenceInvalid
	}
	context := &AttestationContext{AdmitEvent: admit, GovernanceAttestation: attestations[0], GovernanceAttestations: attestations}
	if err = budget.charge(8 * nativeLiveContextMax); err != nil {
		return nil, err
	}
	context, _, err = snapshotAgentContext(context)
	if err != nil || verifyAgentContext(s.journal.selection.artifactRoots, context, s.rootDigest, name, version, s.journal.now().UTC()) != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	if len(archiveBody) > base64.StdEncoding.EncodedLen(nativeLiveArchiveMax)+(nativeLiveArchiveMax/50) || strings.ContainsRune(archiveBody, '\r') {
		return nil, ErrNativeEvidenceInvalid
	}
	if err = budget.charge(int64(len(archiveBody)) + nativeLiveArchiveMax); err != nil {
		return nil, err
	}
	clean := strings.ReplaceAll(archiveBody, "\n", "")
	if len(clean) == 0 || len(clean) > base64.StdEncoding.EncodedLen(nativeLiveArchiveMax) {
		return nil, ErrNativeEvidenceInvalid
	}
	archive, err := base64.StdEncoding.Strict().DecodeString(clean)
	if err != nil || len(archive) == 0 || len(archive) > nativeLiveArchiveMax {
		return nil, ErrNativeEvidenceInvalid
	}
	hash := sha256.Sum256(archive)
	if "sha256:"+hex.EncodeToString(hash[:]) != s.rootDigest {
		return nil, ErrNativeEvidenceInvalid
	}
	return &NativeLiveAgentCandidate{Archive: archive, Bundle: &StagedBundle{Name: name, Version: version, Kind: skillbundle.KindAgent, Digest: s.rootDigest, Governance: s.journal.selection.artifactRoots.GovernanceMinimum, SourceDocID: sourceID, AuthorIdentity: identity, Attestation: context}, workBytes: budget.bytes}, nil
}

func nativeLiveTenant(event map[string]any, s *NativeInstallSession) error {
	a := s.journal.selection.authority
	tenant, exists := event["tenant_scope"]
	if !exists || (a.tenant == nil && tenant != nil) || (a.tenant != nil && tenant != *a.tenant) {
		return ErrNativeEvidenceInvalid
	}
	if registry, exists := event["registry"]; exists && registry != a.registry {
		return ErrNativeEvidenceInvalid
	}
	if event["schema_version"] != EventSchemaVersion {
		return ErrNativeEvidenceInvalid
	}
	return nil
}
