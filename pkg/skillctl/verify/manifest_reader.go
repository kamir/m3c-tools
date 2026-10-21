package verify

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// The limit parameter keeps boundary tests small; production uses MaxBlobSize.
func readDigestVerifiedManifest(r io.Reader, expectedDigest string, limit int64) (map[string]any, error) {
	expected, err := decodeShaHexDigest(expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("verify: invalid expected digest: %w", errors.Join(ErrDigestMismatch, err))
	}
	blob, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	if int64(len(blob)) > limit {
		return nil, fmt.Errorf("verify: compressed bundle exceeds %d bytes", limit)
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("verify: empty bundle: %w", ErrDigestMismatch)
	}
	actual := sha256.Sum256(blob)
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return nil, fmt.Errorf("verify: bundle digest mismatch: %w", ErrDigestMismatch)
	}
	entries, err := skillbundle.Unpack(blob, skillbundle.UnpackOptions{StripWrapper: true})
	if err != nil {
		return nil, fmt.Errorf("unpack bundle: %w", err)
	}
	var manifest []byte
	found := false
	for _, entry := range entries {
		if entry.Rel != "bundle.json" {
			continue
		}
		if found || entry.IsDir {
			return nil, errors.New("verify: ambiguous bundle.json archive entry")
		}
		found, manifest = true, entry.Content
	}
	if !found {
		return nil, errors.New("bundle.json not found in archive")
	}
	if err := validateManifestJSON(manifest); err != nil {
		return nil, fmt.Errorf("decode bundle.json: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(manifest, &out); err != nil {
		return nil, fmt.Errorf("decode bundle.json: %w", err)
	}
	return out, nil
}

func validateManifestJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("manifest must be a JSON object")
	}
	if err := consumeManifestObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("manifest contains trailing JSON or invalid data")
	}
	return nil
}

func consumeManifestObject(dec *json.Decoder, depth int) error {
	seen := make(map[string]struct{})
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("manifest object key is not a string")
		}
		if _, exists := seen[key]; exists {
			return errors.New("manifest contains duplicate JSON keys")
		}
		seen[key] = struct{}{}
		if err := consumeManifestValue(dec, depth); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

func consumeManifestValue(dec *json.Decoder, depth int) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	// Match encoding/json's maximum nesting depth before its final Unmarshal.
	if depth >= 10000 {
		return errors.New("manifest JSON exceeds maximum nesting depth")
	}
	switch delim {
	case '{':
		return consumeManifestObject(dec, depth+1)
	case '[':
		for dec.More() {
			if err := consumeManifestValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		return errors.New("unexpected manifest JSON delimiter")
	}
}
