package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// preparedNativeSkill never escapes the concrete held session. No caller-owned
// map, file path or root reload can alter the retained publication input.
type preparedNativeSkill struct {
	bundle              *StagedBundle
	archive, contextRaw []byte
	entries             []skillbundle.Entry
	manifest            skillbundle.BundleManifest
	roots               *SelfTrustRoots
}

// prepareNativeSkillEvidence performs no filesystem writes. Its caller reserves
// the conservative complete phase cost before invoking this bounded preparation.
func prepareNativeSkillEvidence(b *StagedBundle, archive []byte, opts InstallOpts) (*preparedNativeSkill, error) {
	if b == nil || b.Kind != skillbundle.KindSkill || (!validAgentName(b.Name) || !nativeSkillEntryPath(b.Name)) || !nativeSkillVersionValid(b.Version) || !nativeSubject(b.Digest) || len(archive) == 0 || len(archive) > nativeLiveArchiveMax {
		return nil, ErrNativeEvidenceInvalid
	}
	// Bound all exported metadata before copying/maps/marshal. Stage paths have
	// no meaning in the native retained pipeline and must not be reopened later.
	for _, v := range []string{b.Name, b.Version, b.Digest, b.Kind, b.Governance, b.PackedOnHost, b.AdmittedAt, b.SourceDocID, b.AuthorIdentity, opts.RegistrySpec, opts.ContextID, opts.TrustRootsFingerprint} {
		if len(v) > 8192 || !utf8.ValidString(v) {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	if b.StagedSkbPath != "" || b.ProvenancePath != "" {
		return nil, ErrNativeEvidenceInvalid
	}
	ctx := agentContextOf(opts)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Freeze first; the digest must authenticate the exact retained bytes used
	// by unpack and publication, not a caller slice hashed before copying.
	archive = bytes.Clone(archive)
	if agentDigest(archive) != b.Digest {
		return nil, ErrNativeEvidenceInvalid
	}
	roots, err := snapshotAgentRoots(opts.NativeTrustRoots)
	if err != nil {
		return nil, errors.Join(ErrNativeEvidenceInvalid, err)
	}
	contextSnapshot, contextRaw, err := snapshotAgentContext(b.Attestation)
	if err != nil {
		return nil, errors.Join(ErrNativeEvidenceInvalid, err)
	}
	copyBundle := *b
	copyBundle.Attestation = contextSnapshot
	b = &copyBundle
	if contextSnapshot.AdmitEvent["name"] != b.Name || contextSnapshot.AdmitEvent["version"] != b.Version {
		return nil, ErrNativeEvidenceInvalid
	}
	if err = verifyAgentContext(roots, contextSnapshot, b.Digest, b.Name, b.Version, agentClockOf(opts)); err != nil {
		return nil, errors.Join(ErrNativeEvidenceInvalid, err)
	}
	inflated := skillbundle.DefaultMaxExtractedBytes + int64(skillbundle.DefaultMaxExtractedFiles)*1024 + (1 << 20)
	entries, _, err := skillbundle.UnpackBounded(ctx, archive, skillbundle.UnpackOptions{MaxBytes: skillbundle.DefaultMaxExtractedBytes, MaxFiles: skillbundle.DefaultMaxExtractedFiles, StripWrapper: false, CanonicalizeMD: false}, inflated)
	if err != nil {
		return nil, errors.Join(ErrNativeEvidenceInvalid, err)
	}
	manifest, err := strictNativeSkillEntries(entries, b)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	// Recheck current signed policy after bounded decoding, before retaining input.
	if err = verifyAgentContext(roots, contextSnapshot, b.Digest, b.Name, b.Version, agentClockOf(opts)); err != nil {
		return nil, errors.Join(ErrNativeEvidenceInvalid, err)
	}
	return &preparedNativeSkill{bundle: b, archive: archive, contextRaw: contextRaw, entries: entries, manifest: manifest, roots: roots}, nil
}

// Use Unicode simple-fold classes without rewriting authenticated paths. Actual
// filesystem normalization aliases are additionally rejected during staging.
func nativeSkillPathKey(rel string) string {
	return strings.Map(func(r rune) rune {
		low := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < low {
				low = next
			}
		}
		return unicode.ToLower(low)
	}, rel)
}

// Validate portable components without rewriting any authenticated archive path.
func nativeSkillEntryPath(rel string) bool {
	if rel == "" || len(rel) > 4096 || !utf8.ValidString(rel) || strings.Contains(rel, "\\") || strings.ContainsFunc(rel, unicode.IsControl) || path.Clean(rel) != rel || strings.HasPrefix(rel, "/") {
		return false
	}
	parts := strings.Split(rel, "/")
	if len(parts) > 128 {
		return false
	}
	for _, part := range parts {
		if len(part) > 255 || strings.ContainsAny(part, `<>"|?*`) || part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") || sanitizeBundleName(part) != nil {
			return false
		}
	}
	return true
}

func nativeSkillReserved(rel string) bool {
	first, _, _ := strings.Cut(nativeSkillPathKey(rel), "/")
	if first == nativeSkillPathKey(AttestationStashName) || first == nativeSkillPathKey(ProvenanceSidecarName) || strings.HasSuffix(first, ".skb") {
		return true
	}
	return first == ".native-skill" || first == ".skillctl-evidence" || strings.HasPrefix(first, ".install-") || strings.HasPrefix(first, ".install-backup-")
}

func strictNativeSkillEntries(entries []skillbundle.Entry, b *StagedBundle) (skillbundle.BundleManifest, error) {
	var man skillbundle.BundleManifest
	if b == nil || len(entries) == 0 || len(entries) > skillbundle.DefaultMaxExtractedFiles {
		return man, ErrNativeEvidenceInvalid
	}
	seen := make(map[string]bool, len(entries))
	dirs := make(map[string]bool, len(entries))
	payload := make(map[string][]byte, len(entries))
	var raw, checksums []byte
	anchor := false
	pathBytes := 0
	spellings := make(map[string]string, len(entries))
	for _, entry := range entries {
		if !nativeSkillEntryPath(entry.Rel) || nativeSkillReserved(entry.Rel) {
			return man, ErrNativeEvidenceInvalid
		}
		pathBytes += len(entry.Rel)
		if pathBytes > 4<<20 {
			return man, ErrNativeEvidenceInvalid
		}
		// Fold once. Each prefix is a slice of the retained full spelling/key,
		// not a freshly allocated folded copy at each depth. Independent Dir
		// operations preserve component positions when Unicode folding changes
		// UTF8 byte length (for example Kelvin sign to ASCII k).
		key := nativeSkillPathKey(entry.Rel)
		for prefix, folded := entry.Rel, key; prefix != "."; prefix, folded = path.Dir(prefix), path.Dir(folded) {
			old, exists := spellings[folded]
			if exists && old != prefix {
				return man, ErrNativeEvidenceInvalid
			}
			if !exists {
				if len(spellings) >= 100000 {
					return man, ErrNativeEvidenceInvalid
				}
				spellings[folded] = prefix
			}
		}
		if _, ok := seen[key]; ok {
			return man, ErrNativeEvidenceInvalid
		}
		seen[key] = true
		dirs[key] = entry.IsDir
		if entry.IsDir {
			if len(entry.Content) != 0 {
				return man, ErrNativeEvidenceInvalid
			}
			continue
		}
		switch entry.Rel {
		case "bundle.json":
			raw = entry.Content
		case "CHECKSUMS":
			checksums = entry.Content
		default:
			// Root anchors/metadata may not survive only as portable spelling aliases.
			if key == "bundle.json" || key == "checksums" || (key == "skill.md" && entry.Rel != "SKILL.md") {
				return man, ErrNativeEvidenceInvalid
			}
			if entry.Rel == "SKILL.md" {
				anchor = true
			}
			payload[entry.Rel] = entry.Content
		}
	}
	// Parent files conflict even if tar omitted explicit parent directory entries.
	for key := range seen {
		for parent := path.Dir(key); parent != "."; parent = path.Dir(parent) {
			if isDir, explicit := dirs[parent]; explicit && !isDir {
				return man, ErrNativeEvidenceInvalid
			}
		}
	}
	object, err := readAgentJSON(raw, maxAgentContext)
	if err != nil {
		return man, ErrNativeEvidenceInvalid
	}
	// Malformed critical identity/schema always takes precedence over an
	// otherwise unsupported dependency declaration.
	for key := range object {
		fold := strings.NewReplacer("_", "", "-", "").Replace(nativeSkillPathKey(key))
		for _, canonical := range []string{"schema", "kind", "name", "version", "bundle_digest", "intent"} {
			if fold == strings.ReplaceAll(canonical, "_", "") && key != canonical {
				return man, ErrNativeEvidenceInvalid
			}
		}
	}
	schema, schemaOK := object["schema"].(string)
	name, nameOK := object["name"].(string)
	version, versionOK := object["version"].(string)
	if !schemaOK || schema != skillbundle.Schema || !nameOK || name != b.Name || !versionOK || version != b.Version || !nativeSkillVersionValid(version) || !anchor {
		return man, ErrNativeEvidenceInvalid
	}
	if value, exists := object["kind"]; exists {
		kind, ok := value.(string)
		if !ok || (kind != "" && kind != skillbundle.KindSkill) {
			return man, ErrNativeEvidenceInvalid
		}
	}
	if value, exists := object["bundle_digest"]; exists {
		if _, ok := value.(string); !ok {
			return man, ErrNativeEvidenceInvalid
		}
	}
	for key := range object {
		fold := strings.NewReplacer("_", "", "-", "").Replace(nativeSkillPathKey(key))
		for _, canonical := range []string{"depends_on", "data_dependencies", "package_dependencies"} {
			if fold == strings.ReplaceAll(canonical, "_", "") && key != canonical {
				return man, ErrNativeDependenciesUnavailable
			}
		}
	}
	if err := nativeEmptyAgentDependencies(entries); err != nil {
		return man, err
	}
	if json.Unmarshal(raw, &man) != nil || man.Schema != skillbundle.Schema || man.EffectiveKind() != skillbundle.KindSkill || man.Name != b.Name || man.Version != b.Version || !anchor {
		return man, ErrNativeEvidenceInvalid
	}
	if err = skillbundle.ValidateManifestDataScope(man); err != nil {
		return man, ErrNativeEvidenceInvalid
	}
	if err = nativeSkillChecksums(checksums, payload); err != nil {
		return man, err
	}
	return man, nil
}

// Native checksum spelling is exactly Pack's payload-only format. The signed
// archive authenticates synthesized bundle.json and CHECKSUMS themselves.
func nativeSkillChecksums(raw []byte, payload map[string][]byte) error {
	if len(raw) == 0 {
		return ErrNativeEvidenceInvalid
	}
	if len(raw) > maxAgentContext || !utf8.Valid(raw) || raw[len(raw)-1] != '\n' {
		return ErrNativeEvidenceInvalid
	}
	names := make([]string, 0, len(payload))
	for name := range payload {
		names = append(names, name)
	}
	sort.Strings(names)
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	if len(lines) != len(names) {
		return ErrNativeEvidenceInvalid
	}
	for i, line := range lines {
		name := names[i]
		if len(line) != 66+len(name) || string(line[64:66]) != "  " || string(line[66:]) != name {
			return ErrNativeEvidenceInvalid
		}
		sum := sha256.Sum256(payload[name])
		want := hex.EncodeToString(sum[:])
		if string(line[:64]) != want {
			return ErrNativeEvidenceInvalid
		}
	}
	return nil
}
