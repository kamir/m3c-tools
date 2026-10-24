package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

type importOptions struct {
	target, apiKey, keyOrigin, userID, input          string
	paths                                             []string
	recursive, includeHome, dryRun, allowLoopbackHTTP bool
}

func parseImportArgs(args []string) (importOptions, error) {
	var opts importOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--recursive":
			opts.recursive = true
			continue
		case "--include-home":
			opts.includeHome = true
			continue
		case "--dry-run":
			opts.dryRun = true
			continue
		case "--allow-loopback-http":
			opts.allowLoopbackHTTP = true
			continue
		}
		var dest *string
		switch args[i] {
		case "--target":
			dest = &opts.target
		case "--api-key":
			dest = &opts.apiKey
		case "--api-key-origin":
			dest = &opts.keyOrigin
		case "--user-id":
			dest = &opts.userID
		case "--input":
			dest = &opts.input
		case "--path":
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "--") {
				return opts, errors.New("--path requires a value")
			}
			i++
			opts.paths = append(opts.paths, args[i])
			continue
		default:
			if args[i] != "" && !strings.HasPrefix(args[i], "-") {
				opts.input = args[i]
				continue
			}
			return opts, errors.New("unknown import flag")
		}
		if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "--") {
			return opts, fmt.Errorf("%s requires a value", args[i])
		}
		i++
		*dest = args[i]
	}
	if opts.target == "" {
		return opts, errors.New("--target <url> is required")
	}
	return opts, nil
}

// selectImportCredential validates the target before examining ambient source
// priority. A selected source never falls back after a binding/read failure.
// Origin assignments describe local operator intent, not issuer or tenant proof.
func selectImportCredential(opts importOptions, getenv func(string) string, readSession func() string) (httpsafe.DeferredSecret, error) {
	if _, err := httpsafe.ParseAPIBase(opts.target, opts.allowLoopbackHTTP); err != nil {
		return httpsafe.DeferredSecret{}, err
	}
	kind := httpsafe.CredentialAPIKey
	origin := opts.keyOrigin
	if origin == "" {
		origin = getenv("M3C_API_KEY_ORIGIN")
	}
	key := opts.apiKey
	source := "import-flag-operator-assignment"
	if key == "" {
		if bearer := getenv("ER1_DEVICE_TOKEN"); bearer != "" {
			kind = httpsafe.CredentialDeviceBearer
			origin = getenv("ER1_DEVICE_TOKEN_ORIGIN")
			key = bearer
			source = "import-bearer-environment-operator-assignment"
		} else {
			key = getenv("M3C_API_KEY")
			source = "import-api-environment-operator-assignment"
			if key == "" {
				source = "import-legacy-session-operator-assignment"
			}
		}
	}
	return httpsafe.DeferredSecret{Binding: httpsafe.CredentialBinding{Version: httpsafe.CredentialBindingVersion, Kind: kind, Origin: origin, Source: source}, Read: func() ([]byte, error) {
		selected := key
		if selected == "" {
			selected = readSession()
		}
		selected = strings.TrimSpace(selected)
		if strings.ContainsAny(selected, "\r\n\x00") {
			return nil, errors.New("invalid import credential format")
		}
		return []byte(selected), nil
	}}, nil
}

// decodeLegacySessionAPIKey rejects ambiguous top-level fields, including JSON
// escaped aliases. Context-only sessions and nonstring/empty keys are not keys.
func decodeLegacySessionAPIKey(data []byte) (string, error) {
	invalid := errors.New("legacy session API key missing, invalid or ambiguous")
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return "", invalid
	}
	seen := make(map[string]bool)
	var key string
	for dec.More() {
		token, err = dec.Token()
		if err != nil {
			return "", invalid
		}
		name, ok := token.(string)
		if !ok || seen[name] || (strings.EqualFold(name, "api_key") && name != "api_key") {
			return "", invalid
		}
		seen[name] = true
		var raw json.RawMessage
		if err = dec.Decode(&raw); err != nil {
			return "", invalid
		}
		if name == "api_key" {
			if err = json.Unmarshal(raw, &key); err != nil {
				return "", invalid
			}
		}
	}
	if _, err = dec.Token(); err != nil {
		return "", invalid
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return "", invalid
	}
	if strings.TrimSpace(key) == "" {
		return "", invalid
	}
	return key, nil
}
