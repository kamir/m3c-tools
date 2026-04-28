// Package setup is the foundation of the SPEC-0175 onboarding flow.
//
// All UI-agnostic logic for first-launch + credential validation lives here so
// that both the CLI (m3c-tools setup pocket-key …) and the eventual Cocoa
// wizard call into the same code paths.
package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultPocketBaseURL matches pkg/pocket.DefaultAPIBaseURL but is duplicated
// here to keep this package free of pkg/pocket imports (so pkg/pocket can
// later import setup if needed without a cycle).
const DefaultPocketBaseURL = "https://public.heypocketai.com/api/v1"

// PocketKeyVerdict is the structured outcome of validating a Pocket API key
// against the live heypocketai.com REST API. The Cocoa wizard renders one of
// the three states (Valid / Unauthorized / Unreachable) as green / red /
// yellow markers; the CLI prints a one-line equivalent.
type PocketKeyVerdict struct {
	// State is one of "valid", "unauthorized", "unreachable".
	State string

	// RecordingCount, when State=="valid", is the total number of recordings
	// the account has ever produced (parsed from the pagination envelope).
	RecordingCount int

	// HumanMessage is a one-line summary suitable for direct display.
	HumanMessage string

	// Detail carries the raw error message or HTTP status line for diagnostics.
	Detail string
}

// IsValid is a convenience for callers that just want a yes/no.
func (v PocketKeyVerdict) IsValid() bool { return v.State == "valid" }

// ValidatePocketKey hits GET /public/recordings?limit=1 with the supplied
// Bearer key and classifies the result. baseURL may be empty (uses default).
//
// Three terminal states:
//   - 200 + valid envelope → state=valid + RecordingCount from pagination.Total
//   - 401 / 403            → state=unauthorized (key rejected)
//   - everything else      → state=unreachable (network down, 5xx, malformed body)
//
// Always returns a non-nil verdict; never returns an error itself. The Detail
// field carries the underlying technical reason for unreachable / unauthorized.
func ValidatePocketKey(httpClient *http.Client, baseURL, key string) PocketKeyVerdict {
	if strings.TrimSpace(key) == "" {
		return PocketKeyVerdict{
			State:        "unauthorized",
			HumanMessage: "Empty API key. Paste the pk_… value from the Pocket app.",
			Detail:       "empty key",
		}
	}
	if baseURL == "" {
		baseURL = DefaultPocketBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	url := strings.TrimRight(baseURL, "/") + "/public/recordings?limit=1"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return PocketKeyVerdict{
			State:        "unreachable",
			HumanMessage: "Could not build request to Pocket. Check the API URL.",
			Detail:       err.Error(),
		}
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(key))
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return PocketKeyVerdict{
			State:        "unreachable",
			HumanMessage: "Couldn't reach Pocket. Check your internet connection or try again.",
			Detail:       err.Error(),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return PocketKeyVerdict{
			State:        "unauthorized",
			HumanMessage: "Pocket rejected this key. Double-check it at https://app.heypocket.com/app/settings/api-keys",
			Detail:       fmt.Sprintf("HTTP %d", resp.StatusCode),
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PocketKeyVerdict{
			State:        "unreachable",
			HumanMessage: "Pocket returned an unexpected error. The service may be down — saving anyway, retry later.",
			Detail:       fmt.Sprintf("HTTP %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return PocketKeyVerdict{
			State:        "unreachable",
			HumanMessage: "Pocket connection dropped mid-response. Retry the validation.",
			Detail:       err.Error(),
		}
	}

	var env struct {
		Success    bool `json:"success"`
		Pagination *struct {
			Total int `json:"total"`
		} `json:"pagination"`
	}
	if jsonErr := json.Unmarshal(body, &env); jsonErr != nil {
		return PocketKeyVerdict{
			State:        "unreachable",
			HumanMessage: "Pocket returned an unexpected response shape.",
			Detail:       jsonErr.Error(),
		}
	}
	if !env.Success {
		return PocketKeyVerdict{
			State:        "unauthorized",
			HumanMessage: "Pocket rejected this key (success=false).",
			Detail:       "envelope success flag false",
		}
	}

	count := 0
	if env.Pagination != nil {
		count = env.Pagination.Total
	}

	msg := fmt.Sprintf("Looks good — %d recording%s on this account", count, plural(count))
	return PocketKeyVerdict{
		State:          "valid",
		RecordingCount: count,
		HumanMessage:   msg,
		Detail:         "HTTP 200",
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ErrInvalidKey is returned by callers that want an error type instead of a
// verdict. Most call sites should use ValidatePocketKey directly; this is for
// the rare case where idiomatic Go errors are simpler.
var ErrInvalidKey = errors.New("pocket api key invalid")
