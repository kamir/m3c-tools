package registry

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

func decodeBoundIdentity(raw []byte, expectedID string) (*Identity, error) {
	if !utf8.Valid(raw) {
		return nil, ErrIdentityResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := identityJSONValue(decoder, 0, new(int)); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrIdentityResponse
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, ErrIdentityResponse
	}
	for key := range fields {
		for _, canonical := range []string{"id", "pubkey", "pubkey_b64", "auth_source", "revoked_at"} {
			if key != canonical && strings.EqualFold(key, canonical) {
				return nil, ErrIdentityResponse
			}
		}
	}
	read := func(key string) (string, bool) {
		value, ok := fields[key]
		if !ok {
			return "", true
		}
		var s string
		if json.Unmarshal(value, &s) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return "", false
		}
		return s, true
	}
	id, ok := read("id")
	if !ok || id != expectedID {
		return nil, ErrIdentityResponse
	}
	auth, ok := read("auth_source")
	if !ok || !safeIdentityText(auth, 512, false) {
		return nil, ErrIdentityResponse
	}
	revoked, ok := read("revoked_at")
	if !ok || !safeIdentityText(revoked, 128, true) {
		return nil, ErrIdentityResponse
	}
	key, ok := read("pubkey_b64")
	if !ok {
		return nil, ErrIdentityResponse
	}
	alt, ok := read("pubkey")
	if !ok {
		return nil, ErrIdentityResponse
	}
	decode := func(s string) ([]byte, error) {
		if len(s) > 128 {
			return nil, ErrIdentityResponse
		}
		b, e := base64.StdEncoding.DecodeString(s)
		if e != nil || len(b) != 32 {
			return nil, ErrIdentityResponse
		}
		return b, nil
	}
	if _, present := fields["pubkey_b64"]; present && key == "" {
		return nil, ErrIdentityResponse
	}
	if key == "" {
		key = alt
	}
	first, err := decode(key)
	if err != nil {
		return nil, err
	}
	if _, present := fields["pubkey"]; present {
		second, err := decode(alt)
		if err != nil || !bytes.Equal(first, second) {
			return nil, ErrIdentityResponse
		}
	}
	return &Identity{ID: id, PubkeyB64: base64.StdEncoding.EncodeToString(first), AuthSource: auth, RevokedAt: revoked}, nil
}

func identityJSONToken(d *json.Decoder, count *int) (json.Token, error) {
	if *count >= IdentityJSONTokens {
		return nil, ErrIdentityResponse
	}
	*count++
	return d.Token()
}

func identityJSONValue(d *json.Decoder, depth int, count *int) error {
	token, err := identityJSONToken(d, count)
	if err != nil {
		return ErrIdentityResponse
	}
	if _, nested := token.(json.Delim); nested && depth >= 32 {
		return ErrIdentityResponse
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, err := identityJSONToken(d, count)
			if err != nil {
				return ErrIdentityResponse
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return ErrIdentityResponse
			}
			seen[key] = true
			if err := identityJSONValue(d, depth+1, count); err != nil {
				return err
			}
		}
		t, err := identityJSONToken(d, count)
		if err != nil || t != json.Delim('}') {
			return ErrIdentityResponse
		}
	case json.Delim('['):
		for d.More() {
			if err := identityJSONValue(d, depth+1, count); err != nil {
				return err
			}
		}
		t, err := identityJSONToken(d, count)
		if err != nil || t != json.Delim(']') {
			return ErrIdentityResponse
		}
	}
	return nil
}
