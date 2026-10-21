package registry

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Read the cache once; all downstream consumers receive this bound snapshot.
func readBoundInstallSnapshot(path, expected string) ([]byte, error) {
	// Local staged/cache bundle path selected by the pull/install flow; no path sandbox is promised.
	// #nosec G304 -- intentionally reading the local staged bundle; bytes are bounded and digest-bound before dispatch.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readInstallSnapshot(f, expected, MaxBlobSize)
}

func readInstallSnapshot(r io.Reader, expected string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(expected, "sha256:") || len(expected) != len("sha256:")+sha256.Size*2 {
		return nil, fmt.Errorf("install: missing or malformed staged digest: %w", ErrGateDigest)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(expected, "sha256:"))
	if err != nil {
		return nil, fmt.Errorf("install: malformed staged digest: %w", ErrGateDigest)
	}
	blob, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("install: read staged snapshot: %w", err)
	}
	if int64(len(blob)) > limit {
		return nil, fmt.Errorf("install: staged bundle exceeds %d bytes", limit)
	}
	actual := sha256.Sum256(blob)
	if len(blob) == 0 || subtle.ConstantTimeCompare(actual[:], raw) != 1 {
		return nil, fmt.Errorf("install: staged snapshot differs from pulled digest: %w", ErrGateDigest)
	}
	return blob, nil
}
