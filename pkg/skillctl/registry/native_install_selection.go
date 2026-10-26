package registry

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
)

// NativeInstallSelection retains explicit local destinations and independent
// artifact and revocation authorities. It does not grant an installation.
type NativeInstallSelection struct {
	profileDigest, selectionID, project, home string
	artifactRoots                             *SelfTrustRoots
	authority                                 *NativeRevocationAuthority
	runtimeRaw                                []byte
	projectInfo, homeInfo                     os.FileInfo
}

// NewNativeInstallSelection snapshots bounded policy. Authority is never loaded
// from an ambient profile, key file, credential store or caller callback.
func NewNativeInstallSelection(profileDigest, selectionID, projectRoot, artifactHome string, artifactRoots *NativeRootsSnapshot, authority *NativeRevocationAuthority, runtime dependencies.Profile) (*NativeInstallSelection, error) {
	if !nativeSHA(profileDigest) || !nativeSHA(selectionID) || artifactRoots == nil || authority == nil || len(authority.key) != 32 || authority.historyID == "" {
		return nil, ErrNativeEvidenceInvalid
	}
	project, pi, err := nativePhysicalDirectory(projectRoot)
	if err != nil {
		return nil, err
	}
	home, hi, err := nativePhysicalDirectory(artifactHome)
	if err != nil {
		return nil, err
	}
	// Bound typed inputs before Marshal; ParseProfile then applies the complete
	// runtime contract and returns a separate copy, including literal argv.
	if !nativeRuntimeBudget(runtime) {
		return nil, ErrNativeEvidenceInvalid
	}
	raw, err := json.Marshal(runtime)
	if err != nil || len(raw) > 64<<10 {
		return nil, ErrNativeEvidenceInvalid
	}
	parsed, err := dependencies.ParseProfile(raw)
	if err != nil || parsed.ProjectRoot != project {
		return nil, ErrNativeEvidenceInvalid
	}
	roots, err := snapshotAgentRoots(artifactRoots.roots)
	if err != nil || roots.Registry != authority.registry {
		return nil, ErrNativeEvidenceInvalid
	}
	a, err := authority.WithPolicy(authority.minimumEpoch, authority.maxAge)
	if err != nil {
		return nil, err
	}
	return &NativeInstallSelection{profileDigest: profileDigest, selectionID: selectionID, project: project, home: home, artifactRoots: roots, authority: a, runtimeRaw: raw, projectInfo: pi, homeInfo: hi}, nil
}

func nativeRuntimeBudget(p dependencies.Profile) bool {
	if len(p.Tools) > 128 || len(p.Schema) > 128 || len(p.ProjectRoot) > 4096 {
		return false
	}
	n := len(p.Schema) + len(p.ProjectRoot)
	if p.Python != nil {
		for _, s := range []string{p.Python.Path, p.Python.SitePackages, p.Python.TreeDigest, p.Python.InterpreterRootDigest} {
			if len(s) > 4096 {
				return false
			}
			n += len(s)
		}
	}
	for _, t := range p.Tools {
		if len(t.Name) > 128 || len(t.Path) > 4096 || len(t.VersionPattern) > 512 || len(t.Args) > 16 {
			return false
		}
		n += len(t.Name) + len(t.Path) + len(t.VersionPattern) + 192
		for _, a := range t.Args {
			if len(a) > 256 {
				return false
			}
			n += len(a) + 3
		}
		if n > (64<<10)/6 {
			return false
		}
	}
	return n <= (64<<10)/6
}

func nativeSHA(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func nativePhysicalDirectory(path string) (string, os.FileInfo, error) {
	if !agentText(path, 4096) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", nil, ErrNativeEvidenceInvalid
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, ErrNativeEvidenceInvalid
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, ErrNativeEvidenceInvalid
	}
	return canonical, info, nil
}

func (s *NativeInstallSelection) validate() error {
	if s == nil || s.artifactRoots == nil || s.authority == nil || s.projectInfo == nil || s.homeInfo == nil || !nativeSHA(s.profileDigest) || !nativeSHA(s.selectionID) {
		return ErrNativeEvidenceInvalid
	}
	for _, row := range []struct {
		path string
		info os.FileInfo
	}{{s.project, s.projectInfo}, {s.home, s.homeInfo}} {
		path, info, err := nativePhysicalDirectory(row.path)
		if err != nil || path != row.path || !os.SameFile(info, row.info) {
			return ErrNativeEvidenceInvalid
		}
	}
	return nil
}
