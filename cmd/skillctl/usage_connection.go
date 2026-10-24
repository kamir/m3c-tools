package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

type usageConnectionOptions struct {
	Target            string
	APIKey            string
	KeyOrigin         string
	AllowLoopbackHTTP bool
}

func parseUsageConnectionArgs(args []string) (usageConnectionOptions, error) {
	var opts usageConnectionOptions
	for i := 0; i < len(args); i++ {
		if args[i] == "--allow-loopback-http" {
			opts.AllowLoopbackHTTP = true
			continue
		}
		var dest *string
		switch args[i] {
		case "--target":
			dest = &opts.Target
		case "--api-key":
			dest = &opts.APIKey
		case "--api-key-origin":
			dest = &opts.KeyOrigin
		default:
			return opts, errors.New("unknown sync-usage flag")
		}
		if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "--") {
			return opts, fmt.Errorf("%s requires a value", args[i])
		}
		i++
		*dest = args[i]
	}
	return opts, nil
}

// resolveUsageConnection requires a deliberate operator origin assignment. It
// never infers ownership of an ambient or legacy key from the current target.
// The assignment is local provenance, not an authenticated issuer/tenant claim.
func resolveUsageConnection(opts usageConnectionOptions, getenv func(string) string, readSession func() string) (httpsafe.ResolvedCredential, error) {
	target := opts.Target
	if target == "" {
		target = getenv("M3C_API_URL")
	}
	if target == "" {
		target = "https://onboarding.guide"
	}
	origin := opts.KeyOrigin
	if origin == "" {
		origin = getenv("M3C_API_KEY_ORIGIN")
	}
	return httpsafe.ResolveCredential(target, opts.AllowLoopbackHTTP, httpsafe.DeferredSecret{
		Binding: httpsafe.CredentialBinding{
			Version: httpsafe.CredentialBindingVersion,
			Kind:    httpsafe.CredentialAPIKey,
			Origin:  origin,
			Source:  "sync-usage-operator-assignment",
		},
		Read: func() ([]byte, error) {
			key := opts.APIKey
			if key == "" {
				key = getenv("M3C_API_KEY")
			}
			if key == "" {
				key = readSession()
			}
			key = strings.TrimSpace(key)
			if strings.ContainsAny(key, "\r\n\x00") {
				return nil, errors.New("invalid API key format")
			}
			return []byte(key), nil
		},
	})
}
