package verify

import (
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// AssessBundleRuntimeDependencies assesses only runtime declarations in the
// bounded archive snapshot matching expectedDigest. The caller must separately
// authenticate that digest; this function does not verify author signatures,
// resolve dependencies, assess data_dependencies, or enforce installation policy.
func AssessBundleRuntimeDependencies(bundlePath, expectedDigest string) (*skillbundle.RuntimeDeclarationAssessment, error) {
	manifest, err := ReadDigestVerifiedManifest(bundlePath, expectedDigest)
	if err != nil {
		return nil, err
	}
	assessment := skillbundle.AssessRuntimeDeclarations(manifest)
	assessment.Source = "digest_bound_manifest"
	assessment.Digest = strings.ToLower(expectedDigest)
	return &assessment, nil
}
