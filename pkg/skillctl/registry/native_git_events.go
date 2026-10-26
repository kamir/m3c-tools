package registry

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

type nativeGitRecord struct {
	path, mode, oid string
	raw             []byte
	event           map[string]any
	kind            string
}

func (f *nativeGitFetch) readEvents() error {
	entry, err := f.lookup([]string{"events"})
	if err != nil {
		return err
	}
	if entry.kind != "tree" || entry.mode != "040000" {
		return ErrNativeEvidenceInvalid
	}
	return f.walkEvents("events", entry.oid, 0)
}
func (f *nativeGitFetch) walkEvents(path, oid string, depth int) error {
	if depth > 128 {
		return ErrNativeEvidenceInvalid
	}
	entries, err := f.treeAt(path, oid)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		rel := path + "/" + entry.name
		if err = f.pathCharge(rel); err != nil {
			return err
		}
		if entry.kind == "tree" && entry.mode == "040000" {
			if err = f.walkEvents(rel, entry.oid, depth+1); err != nil {
				return err
			}
			continue
		}
		if entry.kind != "blob" || (entry.mode != "100644" && entry.mode != "100755") || !strings.HasSuffix(entry.name, ".json") || len(f.records) >= 500 {
			return ErrNativeEvidenceInvalid
		}
		raw, e := f.blob(entry.oid, 1<<20)
		if e != nil {
			return e
		}
		if len(raw) > 16<<20-f.eventBytes {
			return ErrNativeEvidenceInvalid
		}
		f.eventBytes += len(raw)
		value, e := nativeGitJSON(raw, 1<<20, f.secret, &f.work)
		if e != nil {
			return e
		}
		event, ok := value.(map[string]any)
		if !ok {
			return ErrNativeEvidenceInvalid
		}
		kind, e := nativeGitEventShape(event)
		if e != nil {
			return e
		}
		f.records = append(f.records, nativeGitRecord{path: rel, mode: entry.mode, oid: entry.oid, raw: raw, event: event, kind: kind})
	}
	return nil
}
func nativeGitText(event map[string]any, key string, max int, empty bool) bool {
	text, ok := event[key].(string)
	return ok && ((empty && text == "") || agentText(text, max))
}
func nativeGitTime(event map[string]any, key string) bool {
	text, ok := event[key].(string)
	if !ok || len(text) > 64 {
		return false
	}
	_, err := time.Parse(time.RFC3339, text)
	return err == nil
}
func nativeGitSignature(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) != 88 {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	return err == nil && len(raw) == 64 && base64.StdEncoding.EncodeToString(raw) == text
}
func nativeGitEventShape(event map[string]any) (string, error) {
	groups := [][]string{{"admitted_by_identity", "signatures", "author_intent", "admitted_at", "blob_uri"}, {"reviewer_id", "governance_level", "attestation_id", "expires_at"}, {"revoked_by", "reason_code", "revoked_at"}, {"installed_on_host", "installed_at", "trust_roots_fingerprint"}}
	selected := -1
	for i, keys := range groups {
		found := false
		for _, key := range keys {
			if _, ok := event[key]; ok {
				found = true
			}
		}
		if found {
			if selected != -1 {
				return "", ErrNativeEvidenceInvalid
			}
			selected = i
		}
	}
	if selected < 0 {
		return "", ErrNativeEvidenceInvalid
	}
	common := []string{"schema_version", "event_id", "occurred_at", "bundle_digest", "tenant_scope", "envelope_signature"}
	required := append([]string(nil), common...)
	optional := []string{}
	kind := ""
	switch selected {
	case 0:
		kind = "admit"
		required = append(required, "name", "version", "author_intent", "admitted_by_identity", "admitted_at", "blob_uri", "signatures")
		optional = []string{"registry", "packed_on_host"}
	case 1:
		kind = "governance"
		required = append(required, "attestation_id", "reviewer_id", "governance_level", "rationale")
		optional = []string{"expires_at", "registry"}
	case 2:
		kind = "revoke"
		required = append(required, "reason_code", "rationale", "revoked_by", "revoked_at")
		optional = []string{"registry"}
	case 3:
		kind = "audit"
		required = append(required, "name", "version", "installed_on_host", "installed_at", "trust_roots_fingerprint", "registry")
	}
	if _, err := nativeGitMap(event, required, optional...); err != nil {
		return "", err
	}
	digest, ok := event["bundle_digest"].(string)
	if !ok || !nativeSubject(digest) || event["schema_version"] != EventSchemaVersion || !nativeGitText(event, "event_id", 8192, false) || !nativeGitTime(event, "occurred_at") || !nativeGitSignature(event["envelope_signature"]) {
		return "", ErrNativeEvidenceInvalid
	}
	if tenant := event["tenant_scope"]; tenant != nil {
		text, ok := tenant.(string)
		if !ok || !agentText(text, 8192) {
			return "", ErrNativeEvidenceInvalid
		}
	}
	for key, value := range event {
		if key == "registry" || key == "packed_on_host" {
			if text, ok := value.(string); !ok || !agentText(text, 8192) {
				return "", ErrNativeEvidenceInvalid
			}
		}
	}
	switch kind {
	case "admit":
		if !nativeGitText(event, "name", 256, false) || !nativeGitText(event, "version", 256, false) || !nativeGitText(event, "admitted_by_identity", 8192, false) || !nativeGitTime(event, "admitted_at") {
			return "", ErrNativeEvidenceInvalid
		}
		intent, _ := event["author_intent"].(string)
		if intent != "green" && intent != "yellow" && intent != "red" {
			return "", ErrNativeEvidenceInvalid
		}
		if uri := event["blob_uri"]; uri != nil {
			if text, ok := uri.(string); !ok || !agentText(text, 8192) {
				return "", ErrNativeEvidenceInvalid
			}
		}
		signatures, ok := event["signatures"].([]any)
		if !ok || len(signatures) < 2 || len(signatures) > 256 {
			return "", ErrNativeEvidenceInvalid
		}
		for _, sig := range signatures {
			m, e := nativeGitMap(sig, []string{"role", "identity_id", "signature_b64", "pubkey_fingerprint"})
			if e != nil || !nativeGitText(m, "identity_id", 8192, false) || !nativeGitSignature(m["signature_b64"]) {
				return "", ErrNativeEvidenceInvalid
			}
			if m["role"] != "author" && m["role"] != "registry" {
				return "", ErrNativeEvidenceInvalid
			}
			finger, ok := m["pubkey_fingerprint"].(string)
			if !ok || !nativeSubject(finger) {
				return "", ErrNativeEvidenceInvalid
			}
		}
	case "governance":
		if !nativeGitText(event, "attestation_id", 8192, false) || !nativeGitText(event, "reviewer_id", 8192, false) || !nativeGitText(event, "rationale", 8192, true) {
			return "", ErrNativeEvidenceInvalid
		}
		level, _ := event["governance_level"].(string)
		if level != "green" && level != "yellow" && level != "red" {
			return "", ErrNativeEvidenceInvalid
		}
		if _, ok := event["expires_at"]; ok && !nativeGitTime(event, "expires_at") {
			return "", ErrNativeEvidenceInvalid
		}
	case "revoke":
		if !nativeGitText(event, "reason_code", 8192, true) || !nativeGitText(event, "rationale", 8192, true) || !nativeGitText(event, "revoked_by", 8192, false) || !nativeGitTime(event, "revoked_at") {
			return "", ErrNativeEvidenceInvalid
		}
	case "audit":
		if !nativeGitText(event, "name", 256, false) || !nativeGitText(event, "version", 256, false) || !nativeGitText(event, "installed_on_host", 8192, false) || !nativeGitTime(event, "installed_at") {
			return "", ErrNativeEvidenceInvalid
		}
		fingerprint, ok := event["trust_roots_fingerprint"].(string)
		if !ok || (fingerprint != "" && !nativeSubject(fingerprint)) {
			return "", ErrNativeEvidenceInvalid
		}
	}
	return kind, nil
}
func (f *nativeGitFetch) selectBundle(digest, kind string) (*StagedBundle, error) {
	var admit map[string]any
	var governance []map[string]any
	var audits []map[string]any
	for _, record := range f.records {
		event := record.event
		if event["bundle_digest"] != digest {
			continue
		}
		// Raw source revocations never establish a new signing role or mutate the
		// journal. All selected revoke shapes deny12, even forged/unknown signers.
		if record.kind == "revoke" {
			return nil, ErrNativeEvidenceInvalid
		}
		if record.kind == "audit" {
			tenant := event["tenant_scope"]
			selected := f.journal.selection.authority.tenant
			if tenant != nil && (selected == nil || tenant != *selected) {
				return nil, ErrNativeEvidenceInvalid
			}
			audits = append(audits, event)
			continue
		}
		if err := nativeLiveTenantSelected(event, f.journal); err != nil {
			return nil, err
		}
		switch record.kind {
		case "admit":
			if admit != nil || event["blob_uri"] != nil {
				return nil, ErrNativeEvidenceInvalid
			}
			admit = event
		case "governance":
			if len(governance) >= 256 || event["governance_level"] == "red" {
				return nil, ErrNativeEvidenceInvalid
			}
			governance = append(governance, event)
		}
	}
	if admit == nil || len(governance) == 0 {
		return nil, ErrNativeEvidenceInvalid
	}
	name, _ := admit["name"].(string)
	version, _ := admit["version"].(string)
	if !validAgentName(name) || !agentText(version, 256) || (kind == skillbundle.KindSkill && !nativeSkillVersionValid(version)) {
		return nil, ErrNativeEvidenceInvalid
	}
	for _, audit := range audits {
		if audit["name"] != name || audit["version"] != version {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	context := &AttestationContext{AdmitEvent: admit, GovernanceAttestation: governance[0], GovernanceAttestations: governance}
	if err := f.work.charge(8 * maxAgentContext); err != nil {
		return nil, err
	}
	context, raw, err := snapshotAgentContext(context)
	if err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	if err = f.work.charge(4 * int64(len(raw)) * int64(len(f.journal.selection.artifactRoots.Signers)+1)); err != nil {
		return nil, err
	}
	f.work.verificationCalls++
	if err = verifyAgentContext(f.journal.selection.artifactRoots, context, digest, name, version, f.journal.now().UTC()); err != nil {
		return nil, ErrNativeEvidenceInvalid
	}
	identity, _ := admit["admitted_by_identity"].(string)
	return &StagedBundle{Name: name, Version: version, Kind: kind, Digest: digest, AuthorIdentity: identity, Attestation: context, Governance: f.journal.selection.artifactRoots.GovernanceMinimum, SourceDocID: "native-git:" + f.source.commit}, nil
}
func (f *nativeGitFetch) proofDigest() (string, error) {
	if err := f.work.charge(int64(len(f.records)) * 256); err != nil {
		return "", err
	}
	ordered := append([]nativeGitRecord(nil), f.records...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].path < ordered[j].path })
	h := sha256.New()
	if _, err := fmt.Fprintf(h, "m3c.native-git-source-proof/v1\x00%d\x00", len(ordered)); err != nil {
		return "", ErrNativeEvidenceInvalid
	}
	for _, record := range ordered {
		if err := f.work.charge(int64(len(record.raw)) + int64(len(record.path)) + 128); err != nil {
			return "", err
		}
		for _, raw := range [][]byte{[]byte(record.path), []byte(record.mode), []byte(record.oid), record.raw} {
			if _, err := fmt.Fprintf(h, "%d%c", len(raw), byte(0)); err != nil {
				return "", ErrNativeEvidenceInvalid
			}
			if _, err := h.Write(raw); err != nil {
				return "", ErrNativeEvidenceInvalid
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (f *nativeGitFetch) checkMetadata() error {
	root, err := f.treeAt("", f.source.tree)
	if err != nil {
		return err
	}
	var dir *nativeGitEntry
	for i := range root {
		if root[i].name == ".skillctl" {
			dir = &root[i]
			break
		}
	}
	if dir == nil {
		return nil
	}
	if dir.kind != "tree" || dir.mode != "040000" {
		return ErrNativeEvidenceInvalid
	}
	entries, err := f.treeAt(".skillctl", dir.oid)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.name != "registry.json" {
			continue
		}
		if entry.kind != "blob" || (entry.mode != "100644" && entry.mode != "100755") {
			return ErrNativeEvidenceInvalid
		}
		raw, e := f.blob(entry.oid, nativeGitMetadataMax)
		if e != nil {
			return e
		}
		v, e := nativeGitJSON(raw, nativeGitMetadataMax, f.secret, &f.work)
		if e != nil {
			return e
		}
		m, e := nativeGitMap(v, []string{"schema_version"}, "created_by", "created_at")
		if e != nil {
			return e
		}
		version, e := nativeGitInteger(m["schema_version"], 1)
		if e != nil || version != 1 {
			return ErrNativeEvidenceInvalid
		}
		for _, key := range []string{"created_by", "created_at"} {
			if _, ok := m[key]; ok && !nativeGitText(m, key, 8192, true) {
				return ErrNativeEvidenceInvalid
			}
		}
		return nil
	}
	return nil
}
