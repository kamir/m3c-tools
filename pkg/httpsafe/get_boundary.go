package httpsafe

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrGETBoundary is a refusal without untrusted URL or credential text.
var ErrGETBoundary = errors.New("HTTP GET leaves the selected registry boundary")

// GETBoundary binds GET requests to one origin and complete path namespace.
// It does not authenticate a server or confine a trusted custom transport.
type GETBoundary struct {
	origin           APIOrigin
	decoded, escaped string
	max              int
	allowHTTP        bool
}

// NewGETBoundary validates the complete base before any credential lookup.
// max counts requests in a redirect chain, matching the existing cap convention.
func NewGETBoundary(base string, allowLoopbackHTTP bool, max int) (*GETBoundary, error) {
	if len(base) > 8192 || max < 1 || max > 32 {
		return nil, ErrGETBoundary
	}
	parsed, err := ParseAPIBase(base, allowLoopbackHTTP)
	if err != nil {
		return nil, ErrGETBoundary
	}
	u, err := url.Parse(parsed.URL)
	if err != nil {
		return nil, ErrGETBoundary
	}
	decoded, escaped, err := boundaryPath(u)
	if err != nil {
		return nil, err
	}
	if decoded != "/" {
		decoded = strings.TrimSuffix(decoded, "/")
		escaped = strings.TrimSuffix(escaped, "/")
	}
	return &GETBoundary{origin: parsed.Origin, decoded: decoded, escaped: escaped, max: max, allowHTTP: allowLoopbackHTTP}, nil
}

func boundaryPath(u *url.URL) (string, string, error) {
	return boundaryPathMode(u, false)
}

func boundaryPathMode(u *url.URL, relativeDots bool) (string, string, error) {
	if u == nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return "", "", ErrGETBoundary
	}
	decoded := u.Path
	if decoded == "" {
		decoded = "/"
	}
	raw := u.EscapedPath()
	if raw == "" {
		raw = "/"
	}
	if len(decoded) > 4096 || len(raw) > 8192 || !utf8.ValidString(decoded) || !strings.HasPrefix(decoded, "/") || strings.ContainsAny(decoded, "\\%") || strings.Contains(decoded, "//") {
		return "", "", ErrGETBoundary
	}
	for _, r := range decoded {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", "", ErrGETBoundary
		}
	}
	if u.RawPath != "" {
		value, err := url.PathUnescape(u.RawPath)
		if err != nil || value != u.Path || u.RawPath != u.EscapedPath() {
			return "", "", ErrGETBoundary
		}
	}
	for _, part := range strings.Split(decoded, "/") {
		if !relativeDots && (part == "." || part == "..") {
			return "", "", ErrGETBoundary
		}
	}
	var normalized strings.Builder
	normalized.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			normalized.WriteByte(raw[i])
			continue
		}
		if i+2 >= len(raw) {
			return "", "", ErrGETBoundary
		}
		b, err := url.PathUnescape(raw[i : i+3])
		if err != nil || len(b) != 1 {
			return "", "", ErrGETBoundary
		}
		c := b[0]
		if c == '/' || c == '\\' || c == '%' || c == '.' || c == '-' || c == '_' || c == '~' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return "", "", ErrGETBoundary
		}
		normalized.WriteString(strings.ToUpper(raw[i : i+3]))
		i += 2
	}
	return decoded, normalized.String(), nil
}

// Validate accepts only body-free GET requests in the selected path namespace.
func (b *GETBoundary) Validate(req *http.Request) error {
	if b == nil || req == nil || req.URL == nil || req.Method != http.MethodGet || req.ContentLength > 0 || len(req.TransferEncoding) != 0 || (req.Body != nil && req.Body != http.NoBody) {
		return ErrGETBoundary
	}
	decoded, escaped, err := boundaryPath(req.URL)
	if err != nil {
		return err
	}
	u := *req.URL
	u.RawQuery = ""
	u.ForceQuery = false
	parsed, err := ParseAPIBase(u.String(), b.allowHTTP)
	if err != nil || parsed.Origin != b.origin {
		return ErrGETBoundary
	}
	within := func(value, prefix string) bool {
		return prefix == "/" || value == prefix || strings.HasPrefix(value, prefix+"/")
	}
	if !within(decoded, b.decoded) || !within(escaped, b.escaped) {
		return ErrGETBoundary
	}
	return nil
}

// CheckRedirect validates every hop; a later return cannot excuse an escape.
func (b *GETBoundary) CheckRedirect(req *http.Request, via []*http.Request) error {
	if b == nil || len(via) >= b.max {
		return ErrGETBoundary
	}
	// Inspect escapes before URL resolution. Literal relative dot segments follow
	// RFC resolution; the resolved request must still stay inside the boundary.
	if req != nil && req.Response != nil {
		if raw := req.Response.Header.Get("Location"); raw != "" {
			location, err := url.Parse(raw)
			if err != nil {
				return ErrGETBoundary
			}
			relative := location.Scheme == "" && location.Host == "" && location.Path != "" && !strings.HasPrefix(location.Path, "/")
			if relative {
				location.Path = "/" + location.Path
				if location.RawPath != "" {
					location.RawPath = "/" + location.RawPath
				}
			}
			if _, _, err := boundaryPathMode(location, relative); err != nil {
				return err
			}
		}
	}
	for _, prior := range via {
		if err := b.Validate(prior); err != nil {
			return err
		}
	}
	return b.Validate(req)
}
