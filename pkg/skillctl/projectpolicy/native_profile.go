package projectpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// NativeSchema selects the native Enterprise mapping. HTTP v1 is separate.
const NativeSchema = "m3c.enterprise-project-profile/v2"

// NativeEvidenceSchema adds an explicit public revocation evidence source.
const NativeEvidenceSchema = "m3c.enterprise-project-profile/v3"

// NativeLiveSchema adds explicit live ER1 credential and TLS selection.
const NativeLiveSchema = "m3c.enterprise-project-profile/v4"

// NativeCarrierSelection is copied operator provenance, not signed carrier origin.
type NativeCarrierSelection struct {
	Kind              string
	Locator           string
	BaseURL           string
	ContextID         string
	AllowLoopbackHTTP bool
}

// NativePolicy retains private role-separated authority and runtime snapshots.
// Offline mutations require the separate enrolled journal and held SDK session.
type NativePolicy struct {
	project, home, digest, selection string
	carrier                          NativeCarrierSelection
	roots                            *registry.NativeRootsSnapshot
	authority                        *registry.NativeRevocationAuthority
	runtime                          dependencies.Profile
	source                           *registry.NativeEvidenceSource
	live                             *registry.NativeLiveAgentSource
	liveSkill                        *registry.NativeLiveSkillSource
	liveBinding                      nativeLiveBinding
}
type nativeDocument struct {
	Schema       string        `json:"schema"`
	ProjectRoot  string        `json:"project_root"`
	ArtifactHome string        `json:"artifact_home"`
	Runtime      fileRef       `json:"runtime"`
	Native       nativeMapping `json:"native"`
}
type nativeMapping struct {
	LogicalRegistry  string  `json:"logical_registry"`
	AuthorityScope   string  `json:"authority_scope"`
	TenantScope      *string `json:"tenant_scope"`
	ArtifactTrust    fileRef `json:"artifact_trust"`
	RevocationTrust  fileRef `json:"revocation_trust"`
	RevocationPolicy struct {
		MinimumEpoch  int64 `json:"minimum_epoch"`
		MaxAgeSeconds int64 `json:"max_age_seconds"`
	} `json:"revocation_policy"`
	Carrier struct {
		Kind              string `json:"kind"`
		Locator           string `json:"locator"`
		BaseURL           string `json:"base_url"`
		ContextID         string `json:"context_id"`
		AllowLoopbackHTTP bool   `json:"allow_loopback_http"`
	} `json:"carrier"`
}

// LoadNative loads one explicit native profile. It never opens a carrier or store.
func LoadNative(path, actualProjectRoot, actualArtifactHome string) (*NativePolicy, error) {
	return loadNative(path, "", actualProjectRoot, actualArtifactHome)
}

// LoadNativePinned checks the one bounded profile read against startup selection.
func LoadNativePinned(path, expectedProfileSHA, actualProjectRoot, actualArtifactHome string) (*NativePolicy, error) {
	if !validSHA(expectedProfileSHA) {
		return nil, ErrInvalid
	}
	return loadNative(path, expectedProfileSHA, actualProjectRoot, actualArtifactHome)
}
func loadNative(path, expected, actualProject, actualHome string) (*NativePolicy, error) {
	for _, v := range []string{path, actualProject, actualHome} {
		if !nativeText(v, 4096) {
			return nil, ErrInvalid
		}
	}
	raw, e := readNativeFile(path, maxProfileBytes)
	if e != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(raw)
	if expected != "" && !equalSHA(sum[:], expected) {
		return nil, ErrSelection
	}
	if !utf8.Valid(raw) || nativeTokenBudget(raw) != nil || strictJSON(raw) != nil {
		return nil, ErrInvalid
	}
	top, e := nativeObject(raw, "schema", "project_root", "artifact_home", "runtime", "native")
	if e != nil {
		return nil, e
	}
	var schema string
	if json.Unmarshal(top["schema"], &schema) != nil || (schema != NativeSchema && schema != NativeEvidenceSchema && schema != NativeLiveSchema) {
		return nil, ErrInvalid
	}
	keys := []string{"logical_registry", "authority_scope", "tenant_scope", "artifact_trust", "revocation_trust", "revocation_policy", "carrier"}
	if schema == NativeEvidenceSchema || schema == NativeLiveSchema {
		keys = append(keys, "revocation_source")
	}
	mapping, e := nativeObjectAllowUnsupported(top["native"], keys...)
	if e != nil {
		return nil, e
	}
	for _, ref := range []json.RawMessage{top["runtime"], mapping["artifact_trust"], mapping["revocation_trust"]} {
		if _, e = nativeObject(ref, "path", "sha256"); e != nil {
			return nil, e
		}
	}
	if _, e = nativeObject(mapping["revocation_policy"], "minimum_epoch", "max_age_seconds"); e != nil {
		return nil, e
	}
	var doc nativeDocument
	if json.Unmarshal(raw, &doc) != nil || doc.Schema != schema {
		return nil, ErrInvalid
	}
	for _, v := range []string{doc.ProjectRoot, doc.ArtifactHome, doc.Runtime.Path, doc.Native.ArtifactTrust.Path, doc.Native.RevocationTrust.Path} {
		if !nativeText(v, 4096) {
			return nil, ErrInvalid
		}
	}
	n := doc.Native
	if !nativeText(n.LogicalRegistry, 8192) || n.AuthorityScope != "key-and-tenant" {
		return nil, ErrUnsupported
	}
	// tenant_scope is mandatory, either null or a nonempty exact string.
	if string(mapping["tenant_scope"]) != "null" && (n.TenantScope == nil || !nativeText(*n.TenantScope, 8192)) {
		return nil, ErrInvalid
	}
	if n.RevocationPolicy.MinimumEpoch < 1 || n.RevocationPolicy.MaxAgeSeconds < 1 || n.RevocationPolicy.MaxAgeSeconds > 86400 {
		return nil, ErrInvalid
	}
	carrier := NativeCarrierSelection{Kind: n.Carrier.Kind}
	if schema == NativeLiveSchema {
		if n.Carrier.Kind != "er1" {
			return nil, ErrUnsupported
		}
		carrier.Locator = n.LogicalRegistry
		carrier.BaseURL = n.Carrier.BaseURL
		carrier.ContextID = n.Carrier.ContextID
	} else {
		switch n.Carrier.Kind {
		case "er1":
			if _, e = nativeObject(mapping["carrier"], "kind", "base_url", "context_id", "allow_loopback_http"); e != nil {
				return nil, e
			}
			var carrierObject map[string]json.RawMessage
			if json.Unmarshal(mapping["carrier"], &carrierObject) != nil || (string(carrierObject["allow_loopback_http"]) != "true" && string(carrierObject["allow_loopback_http"]) != "false") {
				return nil, ErrInvalid
			}
			if !nativeText(n.Carrier.BaseURL, 8192) || !nativeText(n.Carrier.ContextID, 8192) {
				return nil, ErrInvalid
			}
			base, e := httpsafe.ParseAPIBase(n.Carrier.BaseURL, n.Carrier.AllowLoopbackHTTP)
			if e != nil {
				return nil, ErrInvalid
			}
			carrier.BaseURL = strings.TrimRight(base.URL, "/")
			carrier.ContextID = n.Carrier.ContextID
			carrier.AllowLoopbackHTTP = n.Carrier.AllowLoopbackHTTP
			carrier.Locator = n.LogicalRegistry
		case "git":
			if _, e = nativeObject(mapping["carrier"], "kind", "locator"); e != nil {
				return nil, e
			}
			locator := n.Carrier.Locator
			if !nativeText(locator, 4096) || strings.Contains(locator, "@") || strings.ContainsAny(locator, "?#") {
				return nil, ErrUnsupported
			}
			switch {
			case strings.HasPrefix(locator, "local:///"):
				if !filepath.IsAbs(strings.TrimPrefix(locator, "local://")) {
					return nil, ErrInvalid
				}
			case strings.HasPrefix(locator, "gitlab://"), strings.HasPrefix(locator, "github://"):
				rest := strings.TrimPrefix(strings.TrimPrefix(locator, "gitlab://"), "github://")
				if rest == "" || strings.Contains(rest, ":") || strings.Contains(rest, "//") || strings.Contains(rest, "\\") || strings.Contains(rest, "..") || strings.HasSuffix(rest, "/") {
					return nil, ErrInvalid
				}
			default:
				return nil, ErrUnsupported
			}
			carrier.Locator = locator
		default:
			return nil, ErrUnsupported
		}
	}
	project, e1 := canonicalDirectory(doc.ProjectRoot)
	home, e2 := canonicalDirectory(doc.ArtifactHome)
	ap, e3 := canonicalDirectory(actualProject)
	ah, e4 := canonicalDirectory(actualHome)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return nil, ErrInvalid
	}
	if project != ap || home != ah {
		return nil, ErrSelection
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, ErrInvalid
	}
	dir := filepath.Dir(absolute)
	var source *registry.NativeEvidenceSource
	var sourceBinding nativeSourceBinding
	if schema == NativeEvidenceSchema || schema == NativeLiveSchema {
		source, sourceBinding, e = parseNativeEvidenceSource(dir, mapping["revocation_source"])
		if e != nil {
			return nil, e
		}
	}
	var live *registry.NativeLiveAgentSource
	var liveSkill *registry.NativeLiveSkillSource
	var liveBinding nativeLiveBinding
	if schema == NativeLiveSchema {
		live, liveSkill, liveBinding, e = parseNativeLiveSource(dir, mapping["carrier"])
		if e != nil {
			return nil, e
		}
		carrier.BaseURL = liveBinding.BaseURL
		carrier.ContextID = liveBinding.ContextID
	}
	artifactRaw, e := readNativeRef(dir, n.ArtifactTrust, maxTrustBytes)
	if e != nil {
		return nil, e
	}
	revocationRaw, e := readNativeRef(dir, n.RevocationTrust, maxTrustBytes)
	if e != nil {
		return nil, e
	}
	runtimeRaw, e := readNativeRef(dir, doc.Runtime, maxProfileBytes)
	if e != nil {
		return nil, e
	}
	roots, e := registry.ParseNativeRootsSnapshot(artifactRaw)
	if e != nil {
		return nil, nativeAuthorityError(e)
	}
	revocation, e := registry.ParseNativeRootsSnapshot(revocationRaw)
	if e != nil {
		return nil, nativeAuthorityError(e)
	}
	if roots.Roots().Registry != n.LogicalRegistry {
		return nil, ErrSelection
	}
	authority, e := registry.NewNativeRevocationAuthority(n.LogicalRegistry, n.TenantScope, revocation)
	if e != nil {
		return nil, ErrSelection
	}
	authority, e = authority.WithPolicy(n.RevocationPolicy.MinimumEpoch, time.Duration(n.RevocationPolicy.MaxAgeSeconds)*time.Second)
	if e != nil {
		return nil, ErrInvalid
	}
	runtimeProfile, e := dependencies.ParseProfile(runtimeRaw)
	if e != nil {
		return nil, ErrInvalid
	}
	rp, e := canonicalDirectory(runtimeProfile.ProjectRoot)
	if e != nil || rp != project {
		return nil, ErrSelection
	}
	runtimeProfile.ProjectRoot = project
	selectionBytes, e := json.Marshal(struct {
		Domain, Project, Home, Authority string
		Carrier                          NativeCarrierSelection
	}{"m3c.native-selection/v1", project, home, authority.HistoryAuthorityID(), carrier})
	if e != nil {
		return nil, ErrInvalid
	}
	if schema == NativeEvidenceSchema || schema == NativeLiveSchema {
		selectionBytes, e = json.Marshal(struct {
			Domain, Project, Home, Authority string
			Carrier                          NativeCarrierSelection
			Source                           nativeSourceBinding
		}{"m3c.native-selection/v2", project, home, authority.HistoryAuthorityID(), carrier, sourceBinding})
		if e != nil {
			return nil, ErrInvalid
		}
	}
	if schema == NativeLiveSchema {
		selectionBytes, e = json.Marshal(struct {
			Domain, Project, Home, Authority string
			Carrier                          NativeCarrierSelection
			Source                           nativeSourceBinding
			Live                             nativeLiveBinding
		}{"m3c.native-selection/v3", project, home, authority.HistoryAuthorityID(), carrier, sourceBinding, liveBinding})
		if e != nil {
			return nil, ErrInvalid
		}
	}
	selectionSHA := sha256.Sum256(selectionBytes)
	return &NativePolicy{project: project, home: home, digest: hex.EncodeToString(sum[:]), selection: hex.EncodeToString(selectionSHA[:]), carrier: carrier, roots: roots, authority: authority, runtime: runtimeProfile, source: source, live: live, liveSkill: liveSkill, liveBinding: liveBinding}, nil
}
func nativeObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil || len(object) != len(keys) {
		return nil, ErrInvalid
	}
	for _, k := range keys {
		if object[k] == nil {
			return nil, ErrInvalid
		}
	}
	return object, nil
}
func nativeObjectAllowUnsupported(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil, ErrInvalid
	}
	for key := range object {
		if strings.EqualFold(key, "cross_signing") {
			return nil, ErrUnsupported
		}
	}
	return nativeObject(raw, keys...)
}
func nativeText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}
func nativeAuthorityError(e error) error {
	if errors.Is(e, registry.ErrNativeUnsupported) {
		return ErrUnsupported
	}
	return ErrInvalid
}

func (p *NativePolicy) ProjectRoot() string {
	if p == nil {
		return ""
	}
	return p.project
}
func (p *NativePolicy) ArtifactHome() string {
	if p == nil {
		return ""
	}
	return p.home
}
func (p *NativePolicy) ProfileDigest() string {
	if p == nil {
		return ""
	}
	return p.digest
}
func (p *NativePolicy) HistoryAuthorityID() string {
	if p == nil {
		return ""
	}
	return p.authority.HistoryAuthorityID()
}
func (p *NativePolicy) SelectionID() string {
	if p == nil {
		return ""
	}
	return p.selection
}
func (p *NativePolicy) CarrierSelection() NativeCarrierSelection {
	if p == nil {
		return NativeCarrierSelection{}
	}
	return p.carrier
}
func (p *NativePolicy) Intent() *artifact.NativeEnterpriseIntent {
	if p == nil {
		return &artifact.NativeEnterpriseIntent{}
	}
	intent, e := artifact.NewNativeEnterpriseIntent(p.digest, p.selection)
	if e != nil {
		return &artifact.NativeEnterpriseIntent{}
	}
	return intent
}
func (p *NativePolicy) Runtime() dependencies.Profile {
	if p == nil {
		return dependencies.Profile{}
	}
	return *clone(&p.runtime)
}
func (p *NativePolicy) ArtifactRoots() *registry.NativeRootsSnapshot {
	if p == nil {
		return nil
	}
	return p.roots
}
func (p *NativePolicy) ValidateSelection(project, home, carrier string) error {
	if p == nil || !nativeText(project, 4096) || !nativeText(home, 4096) {
		return ErrSelection
	}
	ap, e1 := canonicalDirectory(project)
	ah, e2 := canonicalDirectory(home)
	if e1 != nil || e2 != nil || ap != p.project || ah != p.home || carrier != p.carrier.Locator {
		return ErrSelection
	}
	return nil
}
func (p *NativePolicy) InspectRevocationEvidence(raw []byte) (*registry.NativeEvidenceSnapshot, error) {
	if p == nil {
		return nil, ErrInvalid
	}
	return registry.InspectNativeRevocationEvidence(raw, p.authority)
}

// OfflineInstallSelection binds the SDK's explicit native journal/session path.
// Live carrier mutation remains separately guarded by Intent.
func (p *NativePolicy) OfflineInstallSelection() (*registry.NativeInstallSelection, error) {
	if p == nil {
		return nil, ErrInvalid
	}
	return registry.NewNativeInstallSelection(p.digest, p.selection, p.project, p.home, p.roots, p.authority, p.runtime)
}

// nativeTokenBudget bounds decoding work before object materialization.
func nativeTokenBudget(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	for count := 0; ; count++ {
		_, e := d.Token()
		if e == io.EOF {
			return nil
		}
		if e != nil || count >= 4096 {
			return ErrInvalid
		}
	}
}
func readNativeRef(dir string, ref fileRef, limit int64) ([]byte, error) {
	if !validSHA(ref.SHA256) || !nativeText(ref.Path, 4096) {
		return nil, ErrInvalid
	}
	path := ref.Path
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	raw, e := readNativeFile(path, limit)
	if e != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(raw)
	if !equalSHA(sum[:], ref.SHA256) {
		return nil, ErrSelection
	}
	return raw, nil
}
func readNativeFile(path string, limit int64) (raw []byte, err error) {
	if !nativeText(path, 4096) || limit < 1 || limit > 1<<20 {
		return nil, ErrInvalid
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(canonical))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, root.Close())
		if err != nil {
			raw = nil
		}
	}()
	before, err := root.Lstat(filepath.Base(canonical))
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return nil, ErrInvalid
	}
	f, err := root.Open(filepath.Base(canonical))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			raw = nil
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() > limit {
		return nil, ErrInvalid
	}
	raw, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrInvalid
	}
	after, checkErr := root.Lstat(filepath.Base(canonical))
	if checkErr != nil || !after.Mode().IsRegular() || !os.SameFile(info, after) {
		return nil, ErrInvalid
	}
	return raw, nil
}
