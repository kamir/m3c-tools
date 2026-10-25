package er1

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

var (
	errBoundCredential = errors.New("ER1 credential unavailable or invalid for selected origin; check origin pins and re-login for legacy device tokens")
	errBoundResponse   = errors.New("ER1 response invalid or unsafe")
	errBoundPath       = errors.New("invalid ER1 request path")
)

// BoundOptions selects a final HTTPS base and independently configured credential
// origins. A configured origin selects its family, before either secret is read.
// These operator pins do not authenticate an issuer or tenant.
type BoundOptions struct {
	BaseURL      string
	ContextID    string
	VerifySSL    bool
	BearerOrigin string
	APIKeyOrigin string
}

type boundSources struct {
	readBearer func(string) (string, error)
	readAPIKey func() (string, error)
}

type boundAuthSnapshot struct{ bearer, apiKey string }

func (a *boundAuthSnapshot) reflected(b []byte) bool {
	return (a.bearer != "" && bytes.Contains(b, []byte(a.bearer))) || (a.apiKey != "" && bytes.Contains(b, []byte(a.apiKey)))
}

// decodedReflection checks normal JSON string values and object keys after
// decoding, including standard JSON escapes. It does not decode other formats.
func (a *boundAuthSnapshot) decodedReflection(value any) bool {
	switch v := value.(type) {
	case string:
		return a.reflected([]byte(v))
	case []any:
		for _, item := range v {
			if a.decodedReflection(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range v {
			if a.reflected([]byte(key)) || a.decodedReflection(item) {
				return true
			}
		}
	}
	return false
}

func (a *boundAuthSnapshot) decodeJSON(body []byte) (any, error) {
	if a.reflected(body) {
		return nil, errBoundResponse
	}
	var result any
	if json.Unmarshal(body, &result) != nil || a.decodedReflection(result) {
		return nil, errBoundResponse
	}
	return result, nil
}

// BoundClient captures selected credentials for one operation. Its private
// configuration does not reselect credentials from the environment per request.
type BoundClient struct {
	base      string
	contextID string
	verifySSL bool
	auth      boundAuthSnapshot
}

// NewBoundClient validates all configured pins before reading selected secrets.
// It does not call LoadConfig or probe for unrelated credential families.
func NewBoundClient(options BoundOptions) (*BoundClient, error) {
	return newBoundClient(options, boundSources{
		readBearer: func(base string) (string, error) {
			if value := os.Getenv("ER1_DEVICE_TOKEN"); value != "" {
				return value, nil
			}
			return auth.BoundBearerReadOnly(base, "")
		},
		readAPIKey: func() (string, error) {
			if value := os.Getenv("ER1_API_KEY"); value != "" {
				return value, nil
			}
			if strings.EqualFold(strings.TrimSpace(os.Getenv("M3C_ER1_KEYCHAIN")), "off") {
				return "", errBoundCredential
			}
			return keychainAPIKey(), nil
		},
	})
}

func newBoundClient(options BoundOptions, sources boundSources) (*BoundClient, error) {
	base, err := httpsafe.ParseAPIBase(options.BaseURL, false)
	if err != nil {
		return nil, httpsafe.ErrInvalidAPIBase
	}
	parsed, _ := url.Parse(base.URL)
	if !options.VerifySSL && !boundLoopback(parsed.Hostname()) {
		return nil, httpsafe.ErrInvalidAPIBase
	}
	if unsafeBoundHeader(options.ContextID, false) {
		return nil, errBoundCredential
	}
	if options.BearerOrigin == "" && options.APIKeyOrigin == "" {
		return nil, httpsafe.ErrCredentialBinding
	}
	// Deliberately finish this entire metadata pass before invoking either reader.
	for _, family := range []struct {
		origin string
		kind   httpsafe.CredentialKind
	}{
		{options.BearerOrigin, httpsafe.CredentialDeviceBearer},
		{options.APIKeyOrigin, httpsafe.CredentialAPIKey},
	} {
		if family.origin == "" {
			continue
		}
		_, err := httpsafe.ResolveCredential(base.URL, false, httpsafe.DeferredSecret{
			Binding: httpsafe.CredentialBinding{Version: httpsafe.CredentialBindingVersion, Kind: family.kind, Origin: family.origin, Source: "operator-pin"},
			Read:    func() ([]byte, error) { return []byte("metadata-validation"), nil },
		})
		if err != nil {
			return nil, httpsafe.ErrCredentialBinding
		}
	}
	c := &BoundClient{base: strings.TrimRight(base.URL, "/"), contextID: options.ContextID, verifySSL: options.VerifySSL}
	if options.BearerOrigin != "" {
		if sources.readBearer == nil {
			return nil, errBoundCredential
		}
		c.auth.bearer, err = sources.readBearer(base.URL)
		if err != nil || unsafeBoundHeader(c.auth.bearer, true) {
			return nil, errBoundCredential
		}
	}
	if options.APIKeyOrigin != "" {
		if sources.readAPIKey == nil {
			return nil, errBoundCredential
		}
		c.auth.apiKey, err = sources.readAPIKey()
		if err != nil || unsafeBoundHeader(c.auth.apiKey, true) {
			return nil, errBoundCredential
		}
	}
	return c, nil
}

func unsafeBoundHeader(value string, required bool) bool {
	return (required && (strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value)) || strings.ContainsFunc(value, unicode.IsControl)
}

func boundLoopback(host string) bool {
	return host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func boundRequestError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("ER1 request failed")
}

func (c *BoundClient) endpoint(path string) (string, error) {
	p, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || p.IsAbs() || p.Host != "" || strings.Contains(path, "#") || strings.Contains(p.Path, "\\") || strings.ContainsFunc(path, unicode.IsControl) {
		return "", errBoundPath
	}
	for _, segment := range strings.Split(p.Path, "/") {
		if segment == "." || segment == ".." {
			return "", errBoundPath
		}
	}
	return c.base + path, nil
}

func (c *BoundClient) httpClient() *http.Client {
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: httpsafe.NoCredentialRedirect}
	if !c.verifySSL {
		// #nosec G402 -- constructor requires HTTPS and a parsed loopback hostname.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return client
}

// HTTPGetJSON sends both selected captured headers to a path below the base
// prefix. Status and parse failures do not expose response bodies or URLs.
func (c *BoundClient) HTTPGetJSON(ctx context.Context, path string) (any, error) {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errBoundPath
	}
	if c.auth.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.auth.bearer)
	}
	if c.auth.apiKey != "" {
		req.Header.Set("X-API-KEY", c.auth.apiKey)
	}
	if c.contextID != "" {
		req.Header.Set("X-Context-ID", c.contextID)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, boundRequestError(ctx)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ER1 GET failed (status %d)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (10<<20)+1))
	if err != nil {
		return nil, boundRequestError(ctx)
	}
	if len(body) > 10<<20 {
		return nil, errBoundResponse
	}
	return c.auth.decodeJSON(body)
}

// Upload sends the existing multipart format with captured Bearer preference,
// falling back to the captured API key only when no Bearer family was selected.
func (c *BoundClient) Upload(ctx context.Context, payload *UploadPayload) (*UploadResponse, error) {
	if payload == nil {
		return nil, errors.New("ER1 upload payload missing")
	}
	endpoint, err := c.endpoint("/upload_2")
	if err != nil {
		return nil, err
	}
	cfg := &Config{APIURL: endpoint, APIKey: c.auth.apiKey, ContextID: c.contextID, VerifySSL: c.verifySSL, UploadTimeout: 30, boundAuth: &c.auth}
	return uploadWithContext(ctx, cfg, payload)
}
