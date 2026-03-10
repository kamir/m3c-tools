package transcript

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
)

// ProxyConfig configures proxy support for transcript fetching.
type ProxyConfig interface {
	// GetTransport returns an http.Transport configured with the proxy.
	GetTransport() (*http.Transport, error)
}

// GenericProxyConfig supports HTTP, HTTPS, and SOCKS5 proxies.
type GenericProxyConfig struct {
	// ProxyURL is the proxy URL, e.g. "http://user:pass@host:port" or "socks5://host:port"
	ProxyURL string
	// ProxyAuth is optional "user:password" credentials applied separately from the URL.
	// If set, it overrides any userinfo already embedded in ProxyURL.
	ProxyAuth string
}

// BuildProxyURL returns the effective proxy URL with auth applied.
// Exported so callers and tests can inspect the resolved URL.
func (c *GenericProxyConfig) BuildProxyURL() (string, error) {
	if c.ProxyURL == "" {
		return "", fmt.Errorf("proxy URL is empty")
	}
	if c.ProxyAuth == "" {
		return c.ProxyURL, nil
	}
	parsed, err := url.Parse(c.ProxyURL)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL %q: %w", c.ProxyURL, err)
	}
	parts := strings.SplitN(c.ProxyAuth, ":", 2)
	if len(parts) == 2 {
		parsed.User = url.UserPassword(parts[0], parts[1])
	} else {
		parsed.User = url.User(parts[0])
	}
	return parsed.String(), nil
}

func (c *GenericProxyConfig) GetTransport() (*http.Transport, error) {
	effective, err := c.BuildProxyURL()
	if err != nil {
		return nil, err
	}
	proxyURL, err := url.Parse(effective)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", effective, err)
	}
	return &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}, nil
}

// WebshareProxyConfig supports rotating residential proxies via Webshare.io.
// It picks a random proxy from the list on each request.
type WebshareProxyConfig struct {
	Proxies []string // list of proxy URLs
}

func (c *WebshareProxyConfig) GetTransport() (*http.Transport, error) {
	if len(c.Proxies) == 0 {
		return nil, fmt.Errorf("no proxies configured")
	}
	// Pick a random proxy
	chosen := c.Proxies[rand.Intn(len(c.Proxies))]
	proxyURL, err := url.Parse(chosen)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", chosen, err)
	}
	return &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}, nil
}
