package mutationstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// strictObject accepts only exact field names, once each, and exactly one object.
// The typed decoder checks value shapes; neither format has nested object fields.
func strictObject(raw []byte, fields []string, target any) error {
	if !utf8.Valid(raw) {
		return ErrInvalidState
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrInvalidState
	}
	allowed := make(map[string]bool, len(fields))
	for _, f := range fields {
		allowed[f] = true
	}
	seen := make(map[string]bool)
	for d.More() {
		t, e := d.Token()
		if e != nil {
			return ErrInvalidState
		}
		key, ok := t.(string)
		if !ok || !allowed[key] || seen[key] {
			return ErrInvalidState
		}
		seen[key] = true
		var val json.RawMessage
		if e = d.Decode(&val); e != nil {
			return ErrInvalidState
		}
	}
	if _, err = d.Token(); err != nil {
		return ErrInvalidState
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidState
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err = typed.Decode(target); err != nil {
		return ErrInvalidState
	}
	return nil
}

func (s *Store) authority(raw []byte, now time.Time, fresh bool) (*verify.RevocationList, error) {
	if len(raw) == 0 || len(raw) > MaxEvidenceBytes {
		return nil, ErrInvalidState
	}
	var list verify.RevocationList
	if err := strictObject(raw, []string{"registry_url", "revoked_digests", "issued_at", "epoch", "signature_b64"}, &list); err != nil {
		return nil, err
	}
	if list.Epoch <= 0 {
		return nil, fmt.Errorf("mutation evidence epoch: %w", verify.ErrRegistryNotTrusted)
	}
	if _, err := verify.VerifyRevocationList(&list, s.root, s.root.MinRevocationEpoch); err != nil {
		return nil, fmt.Errorf("mutation evidence signature or registry: %w", verify.ErrRegistryNotTrusted)
	}
	issued, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(list.IssuedAt))
	if err != nil || issued.IsZero() {
		return nil, fmt.Errorf("mutation evidence issuance: %w", verify.ErrRevocationStale)
	}
	if fresh {
		if now.IsZero() || issued.After(now) {
			return nil, fmt.Errorf("mutation evidence clock: %w", verify.ErrRevocationStale)
		}
		policy, err := s.root.Freshness()
		if err != nil {
			return nil, fmt.Errorf("mutation evidence policy: %w", verify.ErrRevocationStale)
		}
		ceiling := 24 * time.Hour
		if policy.MaxStaleness > 0 && policy.MaxStaleness < ceiling {
			ceiling = policy.MaxStaleness
		}
		if now.Sub(issued) > ceiling {
			return nil, fmt.Errorf("mutation evidence stale: %w", verify.ErrRevocationStale)
		}
	}
	return &list, nil
}

func (s *Store) load() (record, *verify.RevocationList, error) {
	var r record
	f, err := openExisting(s.statePath, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = errors.Join(ErrNotEnrolled, err)
		}
		return r, nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	err = errors.Join(readErr, f.Close())
	if err != nil {
		return r, nil, err
	}
	if len(raw) > maxRecordBytes {
		return r, nil, ErrInvalidState
	}
	if err = strictObject(raw, []string{"schema", "registry", "root_fingerprint", "evidence_fingerprint", "epoch", "issued_at", "last_seen", "full_list"}, &r); err != nil {
		return r, nil, err
	}
	if r.Registry != s.registry || r.RootFingerprint != s.fingerprint {
		return r, nil, errors.Join(ErrInvalidState, verify.ErrRegistryNotTrusted)
	}
	if r.Schema != stateSchema || r.EvidenceFingerprint != fingerprint(r.FullList) || r.Epoch <= 0 || r.LastSeen.IsZero() || r.IssuedAt.IsZero() || r.LastSeen.Before(r.IssuedAt) {
		return r, nil, ErrInvalidState
	}
	list, err := s.authority(r.FullList, time.Time{}, false)
	if err != nil {
		return r, nil, errors.Join(ErrInvalidState, err)
	}
	issued, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(list.IssuedAt))
	if list.Epoch != r.Epoch || !issued.Equal(r.IssuedAt) {
		return r, nil, ErrInvalidState
	}
	return r, list, nil
}
