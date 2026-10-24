package httpsafe

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// ErrInvalidAPIBase identifies an invalid or disallowed API base URL.
var ErrInvalidAPIBase = errors.New("invalid or disallowed API base URL")

// APIOrigin is a comparable scheme, canonical hostname and effective port.
// ParseAPIBase constructs origins without DNS or network access.
type APIOrigin struct {
	scheme   string
	hostname string
	port     uint16
}

// String returns a canonical origin, including its effective port.
func (o APIOrigin) String() string {
	if o.scheme == "" {
		return ""
	}
	return o.scheme + "://" + net.JoinHostPort(o.hostname, strconv.Itoa(int(o.port)))
}

// APIBase contains a validated URL with its path prefix preserved and its origin.
// It does not authorize a request path or authenticate a server or credential.
type APIBase struct {
	URL    string
	Origin APIOrigin
}

// ParseAPIBase requires HTTPS unless allowLoopbackHTTP explicitly permits HTTP
// to localhost or a numeric loopback address. Query and fragment delimiters,
// userinfo, controls, whitespace, invalid hosts and invalid ports are rejected.
// DNS names are ASCII only; this helper performs no IDNA conversion or lookup.
func ParseAPIBase(raw string, allowLoopbackHTTP bool) (APIBase, error) {
	if raw == "" || unsafeURLText(raw) || strings.ContainsAny(raw, "?#\\") {
		return APIBase{}, ErrInvalidAPIBase
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || unsafeURLText(u.Path) || strings.Contains(u.Path, "\\") {
		return APIBase{}, ErrInvalidAPIBase
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return APIBase{}, ErrInvalidAPIBase
	}
	hostname := strings.ToLower(u.Hostname())
	addr, ipErr := netip.ParseAddr(hostname)
	if ipErr == nil {
		if addr.Zone() != "" || (addr.Is6() && !strings.HasPrefix(u.Host, "[")) {
			return APIBase{}, ErrInvalidAPIBase
		}
		addr = addr.Unmap()
		hostname = addr.String()
	} else if !validAPIHostname(hostname) {
		return APIBase{}, ErrInvalidAPIBase
	}
	// A bracketed host must be an IPv6 literal, not a DNS name or IPv4 address.
	if strings.HasPrefix(u.Host, "[") && (ipErr != nil || !strings.Contains(u.Hostname(), ":")) {
		return APIBase{}, ErrInvalidAPIBase
	}
	if scheme == "http" && (!allowLoopbackHTTP || (hostname != "localhost" && (ipErr != nil || !addr.IsLoopback()))) {
		return APIBase{}, ErrInvalidAPIBase
	}
	port := 443
	if scheme == "http" {
		port = 80
	}
	if p := u.Port(); p != "" {
		for _, c := range p {
			if c < '0' || c > '9' {
				return APIBase{}, ErrInvalidAPIBase
			}
		}
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return APIBase{}, ErrInvalidAPIBase
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return APIBase{}, ErrInvalidAPIBase
	}
	origin := APIOrigin{scheme: scheme, hostname: hostname, port: uint16(port)}
	u.Scheme = scheme
	u.Host = net.JoinHostPort(hostname, strconv.Itoa(port))
	return APIBase{URL: u.String(), Origin: origin}, nil
}

func unsafeURLText(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}

func validAPIHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
