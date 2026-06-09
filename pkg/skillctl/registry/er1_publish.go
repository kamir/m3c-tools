package registry

// ER1 publish path for the `self` tenant (SPEC-0225 P1). Takes a signed
// SPEC-0190 event + the bundle bytes (for `admitted` events) + a constructed
// tag set, queries ER1 by `skill-digest:` for idempotency, and POSTs the item
// via /upload_2 (multipart text, the same path /session-state and /er1-push
// use). The cmd handler (cmd/skillctl/publish_cmds.go) does all credential and
// signing-key resolution; this file is pure transport.

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
)

// ─── Errors ────────────────────────────────────────────────────────────────

// ErrAlreadyPublished is the idempotency sentinel: an `admitted` item for this
// digest already exists in ER1. Returned by PublishAdmitted; callers should
// treat it as a no-op success and continue.
var ErrAlreadyPublished = errors.New("registry: bundle already published (idempotent no-op)")

// ErrClaimCheckNotImplemented is returned by PublishAdmitted when the bundle
// size exceeds InlineMaxBytes and the operator hasn't supplied a ClaimCheckFn.
// The MinIO overflow path is P1.x / P2 future work; until it lands, the
// runbook keeps bundles inline (the P5 starter manifest is all-inline).
var ErrClaimCheckNotImplemented = errors.New("registry: claim-check (MinIO overflow) path not implemented yet — keep bundles ≤ ER1_INLINE_MAX_BYTES for v1")

// ─── PublishOpts: everything the transport needs, none of it resolved here ─

// SkillMeta is the per-bundle metadata the publisher needs to construct the
// SPEC-0225 §6 tag set. It mirrors the fields the cmd handler already extracts
// from the skill dir + signing step.
type SkillMeta struct {
	Name              string // skill name, used in `skill:` and `skill-version:` tags
	Version           string // version string, used in `skill-version:` tag
	BundleDigest      string // "sha256:<hex>", used in `skill-digest:` tag
	AuthorIdentity    string // "id:kamir@m3c", used in `skill-author:` tag
	GovernanceLevel   string // "green"|"yellow"|"red", used in `governance:` tag
	PackedOnHost      string // short hostname, used in `host:` tag
	ProjectID         string // optional; if set, stamps `project:<id>` for provenance

	// ShareRooms maps the bundle into one or more SPEC-0096 co-learning rooms.
	// Each entry is a room's *room_label* (e.g. "aims-basics") and is stamped as
	// a BARE tag on every event item, so room members can read the bundle via
	// the room tier (room_access.can_view_item: room_label ∈ item.tags). Bare,
	// not `room:<label>` — the ACL matches the label verbatim.
	ShareRooms []string
}

// PublishAdmittedOpts captures the inputs PublishAdmitted needs.
type PublishAdmittedOpts struct {
	// ER1Cfg is the resolved ER1 client config (the cmd handler builds it
	// from ER1_TARGET via pkg/session.ER1Endpoint + Keychain creds).
	ER1Cfg *er1.Config

	// ContextID is the ER1 context for the personal registry (default "skills").
	ContextID string

	// Event is the signed BundleAdmittedEvent (envelope_signature already set).
	Event map[string]any

	// Skill is the per-bundle metadata for the tag set.
	Skill SkillMeta

	// SkbBytes is the .skb file bytes for the inline path. Required iff
	// len(SkbBytes) <= InlineMaxBytes; otherwise ClaimCheckFn must be set.
	SkbBytes []byte

	// InlineMaxBytes is the threshold from ER1_INLINE_MAX_BYTES. 0 means "always inline".
	InlineMaxBytes int

	// ClaimCheckFn, if set, is called for bundles larger than InlineMaxBytes.
	// It should upload SkbBytes to the overflow store (MinIO) and return the
	// blob URI ("minio://<alias>/<bucket>/<digest>"). Stub-only in v1.
	ClaimCheckFn func(skb []byte, digest string) (blobURI string, err error)

	// Now is the wall-clock used in human-readable header timestamps; injectable
	// for tests. Zero means time.Now().
	Now time.Time
}

// PublishAdmittedResult reports the outcome.
type PublishAdmittedResult struct {
	DocID        string // ER1 doc_id of the created item
	Transport    string // "er1-inline" | "er1-claimcheck"
	BlobURI      string // empty for inline
	ItemTags     string // comma-separated tags as posted
	ItemBodySize int    // bytes of the markdown body that was POSTed
}

// PublishAdmitted constructs an ER1 item from a signed BundleAdmittedEvent +
// the bundle bytes, checks idempotency by `skill-digest:`, and POSTs to
// /upload_2. Returns ErrAlreadyPublished (with a result carrying the existing
// DocID) when an admitted item for this digest already exists.
func PublishAdmitted(opts PublishAdmittedOpts) (*PublishAdmittedResult, error) {
	if opts.ER1Cfg == nil {
		return nil, errors.New("PublishAdmitted: ER1Cfg required")
	}
	if opts.ContextID == "" {
		opts.ContextID = "skills"
	}
	if opts.Event == nil {
		return nil, errors.New("PublishAdmitted: Event required")
	}
	if _, ok := opts.Event[EnvelopeSignatureField].(string); !ok {
		return nil, errors.New("PublishAdmitted: Event missing envelope_signature — sign first")
	}
	if opts.Skill.BundleDigest == "" || opts.Skill.Name == "" || opts.Skill.Version == "" {
		return nil, errors.New("PublishAdmitted: Skill.{Name,Version,BundleDigest} required")
	}
	if err := validateDigest(opts.Skill.BundleDigest); err != nil {
		return nil, err
	}

	// Idempotency: does an `admitted` item for this digest already exist?
	if existing, err := findAdmittedByDigest(opts.ER1Cfg, opts.ContextID, opts.Skill.BundleDigest); err != nil {
		// best-effort — log via error return; the caller decides whether to
		// continue. For now we surface the error so the operator sees it.
		return nil, fmt.Errorf("idempotency check: %w", err)
	} else if existing != "" {
		return &PublishAdmittedResult{DocID: existing, Transport: ""}, ErrAlreadyPublished
	}

	// Pick the transport tier.
	transport := "er1-inline"
	var blobURI string
	var inlineSkb []byte
	if opts.InlineMaxBytes > 0 && len(opts.SkbBytes) > opts.InlineMaxBytes {
		if opts.ClaimCheckFn == nil {
			return nil, fmt.Errorf("%w: bundle is %d bytes, ER1_INLINE_MAX_BYTES=%d", ErrClaimCheckNotImplemented, len(opts.SkbBytes), opts.InlineMaxBytes)
		}
		transport = "er1-claimcheck"
		uri, err := opts.ClaimCheckFn(opts.SkbBytes, opts.Skill.BundleDigest)
		if err != nil {
			return nil, fmt.Errorf("claim-check upload: %w", err)
		}
		blobURI = uri
		// Patch the event's blob_uri now that we have it.
		opts.Event["blob_uri"] = blobURI
	} else {
		inlineSkb = opts.SkbBytes
	}

	// Render the item body (header + ```json envelope + optional ```skb-base64).
	body, err := renderAdmittedBody(opts, transport, blobURI, inlineSkb)
	if err != nil {
		return nil, err
	}

	// Tag set per SPEC-0225 §6.1 / WIRE-FORMAT.md §1.
	tags := buildAdmittedTags(opts.Skill, transport, opts.ContextID)

	docID, err := uploadText(opts.ER1Cfg, body, fmt.Sprintf("skill-%s-%s.admitted.md", opts.Skill.Name, opts.Skill.Version), strings.Join(tags, ","), "application/m3c-skill-bundle-event", opts.ContextID)
	if err != nil {
		return nil, fmt.Errorf("upload: %w", err)
	}
	return &PublishAdmittedResult{
		DocID:        docID,
		Transport:    transport,
		BlobURI:      blobURI,
		ItemTags:     strings.Join(tags, ","),
		ItemBodySize: len(body),
	}, nil
}

// PublishAttestedOpts captures the inputs for the attested-event publish path.
type PublishAttestedOpts struct {
	ER1Cfg    *er1.Config
	ContextID string
	Event     map[string]any // signed AttestationPublishedEvent
	Skill     SkillMeta
	Now       time.Time
}

// PublishAttested POSTs an AttestationPublishedEvent item. Not deduped
// (the history of attestations is the point; `registry show` renders it).
func PublishAttested(opts PublishAttestedOpts) (string, error) {
	if opts.ER1Cfg == nil || opts.Event == nil {
		return "", errors.New("PublishAttested: ER1Cfg + Event required")
	}
	if _, ok := opts.Event[EnvelopeSignatureField].(string); !ok {
		return "", errors.New("PublishAttested: Event missing envelope_signature")
	}
	if opts.ContextID == "" {
		opts.ContextID = "skills"
	}
	body, err := renderAttestedBody(opts)
	if err != nil {
		return "", err
	}
	tags := buildAttestedTags(opts.Skill, opts.Event, opts.ContextID)
	return uploadText(opts.ER1Cfg, body, fmt.Sprintf("skill-%s-%s.attested.md", opts.Skill.Name, opts.Skill.Version), strings.Join(tags, ","), "application/m3c-skill-bundle-event", opts.ContextID)
}

// PublishRevokedOpts captures the inputs for the revoked-event publish path.
type PublishRevokedOpts struct {
	ER1Cfg    *er1.Config
	ContextID string
	Event     map[string]any // signed BundleRevokedEvent
	Skill     SkillMeta
	Now       time.Time
}

// PublishInstalledOpts captures the inputs for the install-event publish path.
type PublishInstalledOpts struct {
	ER1Cfg            *er1.Config
	ContextID         string
	Event             map[string]any // signed BundleInstalledEvent
	Skill             SkillMeta
	InstalledOnHost   string
	Now               time.Time
}

// PublishInstalled POSTs a BundleInstalledEvent item with the install-event
// tag set (skill-event:installed, host:<installed-on>). Called by
// `pull --install --emit-installed` so the other machine sees the install.
func PublishInstalled(opts PublishInstalledOpts) (string, error) {
	if opts.ER1Cfg == nil || opts.Event == nil {
		return "", errors.New("PublishInstalled: ER1Cfg + Event required")
	}
	if _, ok := opts.Event[EnvelopeSignatureField].(string); !ok {
		return "", errors.New("PublishInstalled: Event missing envelope_signature")
	}
	if opts.ContextID == "" {
		opts.ContextID = "skills"
	}
	envBytes, err := json.MarshalIndent(opts.Event, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal event: %w", err)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# skill %s@%s — installed on %s\n\n", opts.Skill.Name, opts.Skill.Version, opts.InstalledOnHost)
	fmt.Fprintf(&b, "| | |\n|---|---|\n| digest | `%s` |\n| installed_on | `%s` |\n| installed_at | `%s` |\n| registry | `self` |\n\n",
		opts.Skill.BundleDigest, opts.InstalledOnHost, now.UTC().Format(time.RFC3339))
	b.WriteString("```json\n")
	b.Write(envBytes)
	b.WriteString("\n```\n")

	tags := BuildInstalledTags(opts.Skill, opts.InstalledOnHost)
	return uploadText(opts.ER1Cfg, b.String(), fmt.Sprintf("skill-%s-%s.installed-%s.md", opts.Skill.Name, opts.Skill.Version, opts.InstalledOnHost), strings.Join(tags, ","), "application/m3c-skill-bundle-event", opts.ContextID)
}

// PublishRevoked POSTs a BundleRevokedEvent item.
func PublishRevoked(opts PublishRevokedOpts) (string, error) {
	if opts.ER1Cfg == nil || opts.Event == nil {
		return "", errors.New("PublishRevoked: ER1Cfg + Event required")
	}
	if _, ok := opts.Event[EnvelopeSignatureField].(string); !ok {
		return "", errors.New("PublishRevoked: Event missing envelope_signature")
	}
	if opts.ContextID == "" {
		opts.ContextID = "skills"
	}
	body, err := renderRevokedBody(opts)
	if err != nil {
		return "", err
	}
	tags := buildRevokedTags(opts.Skill, opts.ContextID)
	return uploadText(opts.ER1Cfg, body, fmt.Sprintf("skill-%s-%s.revoked.md", opts.Skill.Name, opts.Skill.Version), strings.Join(tags, ","), "application/m3c-skill-bundle-event", opts.ContextID)
}

// ─── Tag-set builders ──────────────────────────────────────────────────────

func tagPrefixCommon(s SkillMeta, ctxID string) []string {
	t := []string{
		"m3c-skill-bundle",
		fmt.Sprintf("skb-transport-version:%d", SkbTransportVersion),
		"skill:" + s.Name,
		"skill-version:" + s.Name + "@" + s.Version,
		"skill-digest:" + s.BundleDigest,
		"skill-registry:self",
		"skill-author:" + s.AuthorIdentity,
		"claude-code.skill-registry",
	}
	if s.ProjectID != "" {
		t = append(t, "project:"+s.ProjectID)
	}
	// SPEC-0096 room mapping: each room_label is stamped as a bare tag so room
	// members can read the bundle (room_access matches room_label ∈ item.tags).
	for _, room := range s.ShareRooms {
		if r := strings.TrimSpace(room); r != "" {
			t = append(t, r)
		}
	}
	return t
}

func buildAdmittedTags(s SkillMeta, transport, _ string) []string {
	t := tagPrefixCommon(s, "")
	t = append(t,
		"skill-event:"+EventKindAdmitted,
		"governance:"+s.GovernanceLevel,
		"host:"+s.PackedOnHost,
		"transport:"+transport,
	)
	sort.Strings(t)
	return t
}

func buildAttestedTags(s SkillMeta, ev map[string]any, _ string) []string {
	gov, _ := ev["governance_level"].(string)
	t := tagPrefixCommon(s, "")
	t = append(t,
		"skill-event:"+EventKindAttested,
		"governance:"+gov,
	)
	sort.Strings(t)
	return t
}

func buildRevokedTags(s SkillMeta, _ string) []string {
	t := tagPrefixCommon(s, "")
	t = append(t, "skill-event:"+EventKindRevoked)
	sort.Strings(t)
	return t
}

// BuildInstalledTags is exported because the install path (P3) needs it.
func BuildInstalledTags(s SkillMeta, installedOnHost string) []string {
	// Use a copy of the prefix with installed_on_host substituted in `host:`.
	tmp := s
	tmp.PackedOnHost = installedOnHost
	t := tagPrefixCommon(tmp, "")
	t = append(t,
		"skill-event:"+EventKindInstalled,
		"host:"+installedOnHost,
	)
	sort.Strings(t)
	return t
}

// ─── Body renderers ────────────────────────────────────────────────────────

func renderAdmittedBody(opts PublishAdmittedOpts, transport, blobURI string, inlineSkb []byte) (string, error) {
	envBytes, err := json.MarshalIndent(opts.Event, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal event: %w", err)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# skill %s@%s — admitted\n\n", opts.Skill.Name, opts.Skill.Version)
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| digest | `%s` |\n", opts.Skill.BundleDigest)
	fmt.Fprintf(&b, "| governance | `%s` |\n", opts.Skill.GovernanceLevel)
	fmt.Fprintf(&b, "| packed on | `%s` |\n", opts.Skill.PackedOnHost)
	fmt.Fprintf(&b, "| packed at | `%s` |\n", now.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "| transport | `%s` |\n", transport)
	fmt.Fprintf(&b, "| registry | `self` |\n")
	if blobURI != "" {
		fmt.Fprintf(&b, "| blob_uri | `%s` |\n", blobURI)
	}
	b.WriteString("\n```json\n")
	b.Write(envBytes)
	b.WriteString("\n```\n")
	if transport == "er1-inline" && len(inlineSkb) > 0 {
		b.WriteString("\n```skb-base64\n")
		b.WriteString(base64Wrapped(inlineSkb, 76))
		b.WriteString("\n```\n")
	}
	return b.String(), nil
}

func renderAttestedBody(opts PublishAttestedOpts) (string, error) {
	envBytes, err := json.MarshalIndent(opts.Event, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal event: %w", err)
	}
	gov, _ := opts.Event["governance_level"].(string)
	rat, _ := opts.Event["rationale"].(string)
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# skill %s@%s — attested\n\n", opts.Skill.Name, opts.Skill.Version)
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| digest | `%s` |\n", opts.Skill.BundleDigest)
	fmt.Fprintf(&b, "| governance | `%s` |\n", gov)
	fmt.Fprintf(&b, "| reviewer | `%s` |\n", opts.Skill.AuthorIdentity)
	fmt.Fprintf(&b, "| occurred_at | `%s` |\n", now.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "| registry | `self` |\n")
	if rat != "" {
		fmt.Fprintf(&b, "\n**Rationale.** %s\n", rat)
	}
	b.WriteString("\n```json\n")
	b.Write(envBytes)
	b.WriteString("\n```\n")
	return b.String(), nil
}

func renderRevokedBody(opts PublishRevokedOpts) (string, error) {
	envBytes, err := json.MarshalIndent(opts.Event, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal event: %w", err)
	}
	rc, _ := opts.Event["reason_code"].(string)
	rat, _ := opts.Event["rationale"].(string)
	var b strings.Builder
	fmt.Fprintf(&b, "# skill %s@%s — revoked\n\n", opts.Skill.Name, opts.Skill.Version)
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| digest | `%s` |\n", opts.Skill.BundleDigest)
	fmt.Fprintf(&b, "| reason | `%s` |\n", rc)
	fmt.Fprintf(&b, "| revoked_by | `%s` |\n", opts.Skill.AuthorIdentity)
	fmt.Fprintf(&b, "| registry | `self` |\n")
	if rat != "" {
		fmt.Fprintf(&b, "\n**Rationale.** %s\n", rat)
	}
	b.WriteString("\n```json\n")
	b.Write(envBytes)
	b.WriteString("\n```\n")
	return b.String(), nil
}

func base64Wrapped(b []byte, cols int) string {
	enc := base64.StdEncoding.EncodeToString(b)
	if cols <= 0 || len(enc) <= cols {
		return enc
	}
	var out strings.Builder
	for i := 0; i < len(enc); i += cols {
		end := i + cols
		if end > len(enc) {
			end = len(enc)
		}
		if i > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(enc[i:end])
	}
	return out.String()
}

// ─── ER1 transport: upload + tag query ─────────────────────────────────────

// uploadText POSTs a text item to /upload_2 with the given tags. Mirrors the
// pattern in pkg/session.uploadItem (text-only, audio+image placeholders).
//
// IMPORTANT: er1.Upload reads cfg.ContextID for the multipart context_id form
// field. The cmd-level resolveER1Config deliberately clears that field so
// the publish path doesn't accidentally inherit the user's personal default
// from ER1_CONTEXT_ID. Callers (PublishAdmitted/Attested/Revoked/Installed)
// MUST have set opts.ContextID by here; we copy it onto a shallow Config copy
// so the original (shared) pointer isn't mutated mid-batch.
func uploadText(cfg *er1.Config, body, filename, tags, contentType, ctxID string) (string, error) {
	if ctxID == "" {
		return "", fmt.Errorf("uploadText: ContextID required (the publish path forbids implicit personal-default)")
	}
	cfgCopy := *cfg
	cfgCopy.ContextID = ctxID
	resp, err := er1.Upload(&cfgCopy, &er1.UploadPayload{
		TranscriptData:     []byte(body),
		TranscriptFilename: filename,
		Tags:               tags,
		ContentType:        contentType,
	})
	if err != nil {
		return "", err
	}
	return resp.DocID, nil
}

// findAdmittedByDigest queries ER1 for an existing `admitted` item with this
// digest. Returns the DocID if found, "" if not.
//
// Implementation note (SPEC-0225 P5): prod ER1 doesn't have a tag-filtered
// `/memory/<ctx>/search` route that accepts X-API-KEY (the /api/memory/<ctx>/search
// route from SPEC-0222 is session-cookie-only). We fall back to maindrec's
// dual-auth `GET /memory/<ctx>?limit=…&range=year` and filter client-side by
// the required tag set. At personal scale (tens-to-hundreds of skill events)
// this is fine; if the registry ever has thousands of events a paginated
// fetch is the follow-up.
func findAdmittedByDigest(cfg *er1.Config, ctxID, digest string) (string, error) {
	want := []string{
		"m3c-skill-bundle",
		"skill-registry:self",
		"skill-event:" + EventKindAdmitted,
		"skill-digest:" + digest,
	}
	items, err := searchByTagsRaw(cfg, ctxID, want)
	if err != nil {
		return "", err
	}
	for _, item := range items {
		if id, _ := item["doc_id"].(string); id != "" {
			return id, nil
		}
	}
	return "", nil
}

func er1Get(base string, cfg *er1.Config, path string) (any, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	if !cfg.VerifySSL {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range cfg.AuthHeaders() {
		req.Header.Set(k, v)
	}
	if os.Getenv("ER1_DEVICE_TOKEN") == "" && cfg.APIKey != "" {
		req.Header.Set("X-API-KEY", cfg.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// SPEC-0225 P5: the maindrec GET /memory/<ctx>?limit=500&range=year
	// response can hit 13+ MiB on contexts with a year of activity. Cap at
	// 64 MiB — enough headroom for personal scale, still bounded against an
	// adversarial server pumping unbounded bytes at us.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	// 404 = the search endpoint exists but has no matches OR the endpoint
	// itself is absent. Either way, "no items" is the safe semantic for the
	// idempotency and list paths — fail open (return empty list, no error).
	// The publish path treats this as "no prior item, proceed"; the registry
	// view treats it as "registry empty under this filter".
	if resp.StatusCode == 404 {
		// fail open: "no items found" rather than transport error
		return []any{}, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s -> HTTP %d", path, resp.StatusCode)
	}
	var v any
	if err := json.Unmarshal(bytes.TrimSpace(b), &v); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return v, nil
}

func coerceItems(v any) []map[string]any {
	switch x := v.(type) {
	case []any:
		return toMapList(x)
	case map[string]any:
		for _, key := range []string{"items", "results", "memories", "docs"} {
			if inner, ok := x[key].([]any); ok {
				return toMapList(inner)
			}
		}
		return []map[string]any{x}
	}
	return nil
}

func toMapList(xs []any) []map[string]any {
	out := make([]map[string]any, 0, len(xs))
	for _, x := range xs {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
