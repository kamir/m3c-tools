package verify

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// SnapshotResult contains verified retained input and its measured decode usage.
// The caller owns returned maps and entry bytes; they are not immutable tokens.
// On decode failure a nonnil result may contain Usage only, with Verification nil.
type SnapshotResult struct {
	Verification *VerifyResult
	Manifest     map[string]any
	Entries      []skillbundle.Entry
	Usage        skillbundle.UnpackUsage
}
type snapshotInput struct {
	blob   []byte
	limit  int64
	result *SnapshotResult
}

// VerifySnapshot copies bounded retained bytes before hashing, then runs the same
// cryptographic policy checks as Verify. BundlePath must be empty; no filesystem
// bundle path is used, including when deriving signed manifest scopes. Unlike
// advisory scope reads in Verify, this entrypoint requires a valid unique object
// manifest of at most 1 MiB. Callers must reserve a finite per-call budget before
// invocation: early cryptographic failure may return nil without decode usage.
func VerifySnapshot(opts VerifyOpts, blob []byte, maxInflatedBytes int64) (*SnapshotResult, error) {
	if opts.BundlePath != "" || len(blob) == 0 || int64(len(blob)) > registry.MaxBlobSize {
		return nil, fmt.Errorf("verify: invalid snapshot input: %w", ErrDigestMismatch)
	}
	if maxInflatedBytes <= 0 || maxInflatedBytes == math.MaxInt64 {
		return nil, skillbundle.ErrInflatedLimit
	}
	if err := validateChainOpts(opts); err != nil {
		return nil, err
	}
	if opts.Ctx != nil {
		if err := opts.Ctx.Err(); err != nil {
			return nil, err
		}
	}
	retained := append([]byte(nil), blob...)
	digest := sha256.Sum256(retained)
	result := &SnapshotResult{}
	verified, err := verifyDigest(opts, digest, "sha256:"+hexLower(digest[:]), &snapshotInput{blob: retained, limit: maxInflatedBytes, result: result})
	if err != nil {
		if result.Usage.InflatedBytes != 0 || result.Usage.Entries != 0 {
			return result, err
		}
		return nil, err
	}
	if opts.Ctx != nil {
		if err := opts.Ctx.Err(); err != nil {
			return result, err
		}
	}
	if verified == nil {
		return nil, errors.New("verify: snapshot produced no verification")
	}
	result.Verification = verified
	return result, nil
}
