package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
	"github.com/kamir/m3c-tools/pkg/skillctl/mutationstate"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func validateProjectSelection(policy *projectpolicy.Policy, root *verify.TrustRoot, home, url string, ignore, allow bool, governance, tenant string) error {
	if !root.IsManaged() && policy == nil {
		return nil
	}
	if policy == nil || policy.ValidateSelection(root, home, url) != nil {
		return fmt.Errorf("install: explicit matching enterprise project profile required: %w", verify.ErrRegistryNotTrusted)
	}
	if ignore || allow || governance != "" || (tenant != "" && tenant != policy.TrustRoots().TenantScope) {
		return fmt.Errorf("install: enterprise project profile forbids policy overrides: %w", verify.ErrRegistryNotTrusted)
	}
	return nil
}

func prepareProjectDependencies(ctx context.Context, policy *projectpolicy.Policy, blob []byte, verified *verify.VerifyResult, name, expectedVersion string, session *mutationstate.Session) (func() error, error) {
	if policy == nil {
		return nil, nil
	}
	if session == nil {
		return nil, fmt.Errorf("install: enterprise mutation session required: %w", verify.ErrRevocationStale)
	}
	if verified == nil {
		return nil, verify.ErrDigestMismatch
	}
	if err := verifyInstallSnapshot(blob, verified, verified.Digest); err != nil {
		return nil, err
	}
	manifest, err := projectManifest(blob)
	if err != nil {
		return nil, fmt.Errorf("install: invalid retained manifest: %w", verify.ErrDepsUnsatisfied)
	}
	assessment := skillbundle.AssessRuntimeDeclarations(manifest)
	if assessment.Status == skillbundle.RuntimeDependenciesInvalid {
		return nil, fmt.Errorf("install: invalid runtime dependency declarations: %w", verify.ErrDepsUnsatisfied)
	}
	manifestName, ok := manifest["name"].(string)
	version, vok := manifest["version"].(string)
	if !ok || !vok || manifestName != name || (expectedVersion != "" && !strings.HasPrefix(expectedVersion, "sha256:") && version != expectedVersion) {
		return nil, fmt.Errorf("install: signed manifest identity differs from selected artifact: %w", verify.ErrDigestMismatch)
	}
	kind := "skill"
	if value, present := manifest["kind"]; present {
		var ok bool
		kind, ok = value.(string)
		if !ok {
			return nil, verify.ErrDepsUnsatisfied
		}
	}
	if schema, present := manifest["schema"]; present {
		s, ok := schema.(string)
		if !ok || !skillbundle.KnownSchema(s) {
			return nil, verify.ErrDepsUnsatisfied
		}
	}
	if kind == "" {
		kind = "skill"
	}
	if kind != "skill" {
		return nil, fmt.Errorf("install: HTTP project install supports skill bundles only: %w", verify.ErrDepsUnsatisfied)
	}
	for _, d := range assessment.Declarations {
		if d.Kind == "skill" || d.Kind == "agent" {
			if len(d.Name) > 128 {
				return nil, verify.ErrDepsUnsatisfied
			}
			if _, err := CanonicalSkillName(d.Name); err != nil {
				return nil, verify.ErrDepsUnsatisfied
			}
			return nil, fmt.Errorf("install: dependency %s %q requires an already installed cryptographically verified artifact; install or reinstall it from the selected registry after retained-proof support is available: %w", d.Kind, d.Name, verify.ErrDepsUnsatisfied)
		}
	}
	resolver, err := dependencies.NewResolver(policy.Runtime(), nil)
	if err != nil {
		return nil, fmt.Errorf("install: invalid project runtime: %w", verify.ErrDepsUnsatisfied)
	}
	root := dependencies.Artifact{Authority: policy.ProfileDigest(), Kind: kind, Name: manifestName, Version: version, Digest: verified.Digest, Declarations: assessment.Declarations}
	report, err := resolver.Resolve(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("install: project dependencies unresolved: %w", verify.ErrDepsUnsatisfied)
	}
	return func() error {
		if _, err := resolver.Recheck(ctx, root, report.LockDigest); err != nil {
			return fmt.Errorf("install: project dependency recheck failed: %w", errors.Join(verify.ErrDepsUnsatisfied, err))
		}
		if _, err := session.Recheck(ctx); err != nil {
			return managedInstallStateError(err)
		}
		return nil
	}, nil
}

// Parse exactly the retained digest-verified bytes, never a reopened stage path.
func projectManifest(blob []byte) (map[string]any, error) {
	entries, err := skillbundle.Unpack(blob, skillbundle.UnpackOptions{StripWrapper: true})
	if err != nil {
		return nil, err
	}
	var raw []byte
	for _, e := range entries {
		if e.Rel != "bundle.json" {
			continue
		}
		if raw != nil || e.IsDir {
			return nil, verify.ErrDigestMismatch
		}
		raw = e.Content
	}
	if raw == nil || !utf8.Valid(raw) {
		return nil, verify.ErrDigestMismatch
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := manifestJSONValue(dec, 0); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, verify.ErrDigestMismatch
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil || out == nil {
		return nil, verify.ErrDigestMismatch
	}
	for key := range out {
		for _, canonical := range []string{"name", "version", "kind", "schema", "depends_on", "package_dependencies", "data_dependencies"} {
			if key != canonical && strings.EqualFold(key, canonical) {
				return nil, verify.ErrDepsUnsatisfied
			}
		}
	}
	return out, nil
}
func manifestJSONValue(d *json.Decoder, depth int) error {
	if depth > 128 {
		return verify.ErrDigestMismatch
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			t, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := t.(string)
			if !ok || seen[key] {
				return verify.ErrDigestMismatch
			}
			seen[key] = true
			if err := manifestJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		if token, err = d.Token(); err != nil || token != json.Delim('}') {
			return verify.ErrDigestMismatch
		}
	case json.Delim('['):
		for d.More() {
			if err := manifestJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		if token, err = d.Token(); err != nil || token != json.Delim(']') {
			return verify.ErrDigestMismatch
		}
	case json.Delim('}'), json.Delim(']'):
		return verify.ErrDigestMismatch
	}
	return nil
}

// Bound caller-owned metadata before JSON snapshot allocation. Maps are wire
// JSON values, not arbitrary caller objects with custom marshal callbacks.
func snapshotProjectMeta(meta *registry.BundleMeta) (*registry.BundleMeta, error) {
	if meta == nil || len(meta.Signatures) > 4096 || len(meta.Attestations) > 4096 {
		return nil, verify.ErrRegistryNotTrusted
	}
	b := metaBudget{}
	if !b.value(meta.Bundle, 0) || !b.value(meta.Manifest, 0) || !b.text(meta.CurrentGovernance) {
		return nil, verify.ErrRegistryNotTrusted
	}
	for _, s := range meta.Signatures {
		for _, v := range []string{s.Role, s.IdentityID, s.SignatureB64, s.PubkeyFingerprint, s.Status} {
			if !b.text(v) {
				return nil, verify.ErrRegistryNotTrusted
			}
		}
	}
	for _, a := range meta.Attestations {
		for _, v := range []string{a.AttestationID, a.Level, a.ReviewerID, a.AttestedAt, a.Rationale, a.SignatureB64, a.Status, a.TenantScope, a.AuthorID} {
			if !b.text(v) {
				return nil, verify.ErrRegistryNotTrusted
			}
		}
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, verify.ErrRegistryNotTrusted
	}
	var out registry.BundleMeta
	if json.Unmarshal(raw, &out) != nil {
		return nil, verify.ErrRegistryNotTrusted
	}
	return &out, nil
}

type metaBudget struct{ bytes, nodes int }

func (b *metaBudget) text(s string) bool {
	if len(s) > (1<<20)-b.bytes || !utf8.ValidString(s) {
		return false
	}
	b.bytes += len(s)
	return true
}
func (b *metaBudget) value(v any, depth int) bool {
	if depth > 64 || b.nodes >= 16384 {
		return false
	}
	b.nodes++
	switch x := v.(type) {
	case nil, bool, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case string:
		return b.text(x)
	case json.Number:
		return b.text(string(x))
	case map[string]any:
		if len(x) > 16384-b.nodes {
			return false
		}
		for k, v := range x {
			if !b.text(k) || !b.value(v, depth+1) {
				return false
			}
		}
		return true
	case []any:
		if len(x) > 16384-b.nodes {
			return false
		}
		for _, v := range x {
			if !b.value(v, depth+1) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
