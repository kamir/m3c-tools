package install

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// Bind the retained extraction bytes to both the verified and selected identity.
func verifyInstallSnapshot(blob []byte, verified *verify.VerifyResult, selectedDigest string) error {
	if verified == nil || len(blob) == 0 {
		return fmt.Errorf("install: missing verified snapshot: %w", verify.ErrDigestMismatch)
	}
	actual := sha256.Sum256(blob)
	for _, expected := range []string{verified.Digest, selectedDigest} {
		if !strings.HasPrefix(expected, "sha256:") || len(expected) != len("sha256:")+sha256.Size*2 {
			return fmt.Errorf("install: invalid snapshot digest: %w", verify.ErrDigestMismatch)
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(expected, "sha256:"))
		if err != nil || subtle.ConstantTimeCompare(actual[:], raw) != 1 {
			return fmt.Errorf("install: retained bundle differs from verified or selected digest: %w", verify.ErrDigestMismatch)
		}
	}
	return nil
}

func readLocalInstallSnapshot(path string) ([]byte, error) {
	// Operator-selected input is intentional; the retained bytes are bounded
	// here and bound to the verified digest before installation.
	// #nosec G304 -- reading the operator-selected local bundle is intentional.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLocalInstallBytes(f, registry.MaxBlobSize)
}

func readLocalInstallBytes(r io.Reader, limit int64) ([]byte, error) {
	blob, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("install: read local snapshot: %w", err)
	}
	if int64(len(blob)) > limit {
		return nil, fmt.Errorf("install: local bundle exceeds %d bytes", limit)
	}
	return blob, nil
}
