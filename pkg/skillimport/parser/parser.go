// Package parser implements SPEC-0201 §3 reference syntax for the
// untrusted-upstream import airlock.
//
// A public reference uniquely identifies an upstream candidate AT a specific
// content version. The MVP P1-P4 surface accepts two equivalent forms:
//
//	<host>:<owner>/<name>@sha256:<64hex>
//	<host>/<owner>/<name>@sha256:<64hex>
//
// Pinning is mandatory. A reference without an `@sha256:<hex>` suffix is
// rejected with ErrPinRequired (mapped to exit code 4 by the CLI).
package parser

import (
	"errors"
	"fmt"
	"strings"
)

// ErrPinRequired is returned by Parse when the input lacks an `@sha256:<hex>`
// pin. The CLI maps it to exit code 4 per SPEC-0201 §11.
var ErrPinRequired = errors.New("pin required: reference must end with @sha256:<64hex>")

// Reference is a parsed upstream skill reference.
type Reference struct {
	Host  string // e.g. "github.com", "skillhub.club"
	Owner string // e.g. "anthropics", "openai"
	Name  string // e.g. "code-reviewer"
	Pin   string // "sha256:<64hex>" — REQUIRED
	Raw   string // original input string (whitespace-trimmed)
}

// String renders the canonical form (host:owner/name@pin).
func (r *Reference) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s/%s@%s", r.Host, r.Owner, r.Name, r.Pin)
}

// CanonicalSlug returns "<host>/<owner>/<name>" — useful as a staging-dir key
// component below the pin's content-hash directory.
func (r *Reference) CanonicalSlug() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s/%s", r.Host, r.Owner, r.Name)
}

// PinHex returns the 64-char hex digest portion of the pin (without the
// "sha256:" prefix). Returns empty string if the reference has no pin.
func (r *Reference) PinHex() string {
	if r == nil {
		return ""
	}
	return strings.TrimPrefix(r.Pin, "sha256:")
}

// Parse parses a public reference string. See package docs for the accepted
// forms. Returns ErrPinRequired if the pin is missing; returns descriptive
// errors for malformed pins, malformed slugs, or empty fields.
func Parse(input string) (*Reference, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return nil, errors.New("empty reference")
	}

	// 1. Split off the `@sha256:<hex>` pin first; this also detects "missing pin".
	atIdx := strings.Index(raw, "@")
	if atIdx < 0 {
		return nil, ErrPinRequired
	}
	body := raw[:atIdx]
	pin := raw[atIdx+1:]

	if body == "" {
		return nil, errors.New("empty reference body before @pin")
	}

	if err := validatePin(pin); err != nil {
		// A malformed pin is distinct from a missing pin: surface the validation
		// error as-is so the operator sees what's wrong (digest length, casing).
		return nil, err
	}

	// 2. Split host from the owner/name slug.
	//    Accept BOTH "<host>:<owner>/<name>" and "<host>/<owner>/<name>".
	var host, ownerName string
	if colonIdx := strings.Index(body, ":"); colonIdx >= 0 {
		host = body[:colonIdx]
		ownerName = body[colonIdx+1:]
	} else {
		// Find the FIRST slash and split there.
		slashIdx := strings.Index(body, "/")
		if slashIdx < 0 {
			return nil, fmt.Errorf("malformed reference body %q: expected <host>:<owner>/<name> or <host>/<owner>/<name>", body)
		}
		host = body[:slashIdx]
		ownerName = body[slashIdx+1:]
	}

	if host == "" {
		return nil, errors.New("empty host in reference")
	}
	if strings.ContainsAny(host, " \t") {
		return nil, fmt.Errorf("invalid host %q: contains whitespace", host)
	}

	// 3. Split owner/name on the single internal slash.
	parts := strings.Split(ownerName, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed reference: expected <owner>/<name>, got %q", ownerName)
	}
	owner := parts[0]
	name := parts[1]
	if owner == "" {
		return nil, errors.New("empty owner in reference")
	}
	if name == "" {
		return nil, errors.New("empty name in reference")
	}

	return &Reference{
		Host:  host,
		Owner: owner,
		Name:  name,
		Pin:   pin,
		Raw:   raw,
	}, nil
}

// validatePin rejects any pin that is not exactly "sha256:" followed by 64
// lowercase hex characters. This is the only digest scheme this MVP accepts.
func validatePin(pin string) error {
	const prefix = "sha256:"
	if pin == "" {
		return ErrPinRequired
	}
	if !strings.HasPrefix(pin, prefix) {
		return fmt.Errorf("malformed pin %q: must start with %q", pin, prefix)
	}
	hex := pin[len(prefix):]
	if len(hex) != 64 {
		return fmt.Errorf("malformed pin %q: digest must be 64 hex chars (got %d)", pin, len(hex))
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return fmt.Errorf("malformed pin %q: digest must be lowercase hex (bad char at offset %d)", pin, i)
		}
	}
	return nil
}
