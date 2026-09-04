package plaud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// devAPIBase is the Plaud DEVELOPER platform API. Unlike the consumer API
// (api.plaud.ai / api-euc1.plaud.ai, region-redirected), this is a single host
// and is what the official @plaud-ai/mcp OAuth token authenticates against.
const devAPIBase = "https://platform.plaud.ai/developer/api"

// devOAuthClientID is the @plaud-ai/mcp app's PUBLIC OAuth client id (a public
// identifier, NOT a secret. The app is a public/PKCE client). It is required to
// refresh the third-party access token. Baked default from @plaud-ai/mcp.
const devOAuthClientID = "client_37d250cb-50f8-4af1-8cd6-bc6711c5d684"

// devRefreshMargin refreshes the access token this long before its hard expiry.
const devRefreshMargin = 1 * time.Hour

// devCheckRedirect re-validates EVERY redirect hop against the plaud.ai / S3
// allowlists, so a malicious API/detail response cannot redirect a token-bearing
// request or a presigned-audio GET to an internal/attacker host (SSRF).
func devCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("plaud: too many redirects")
	}
	u := req.URL.String()
	if isAllowedS3URL(u) || isAllowedPlaudDomain(u) {
		return nil
	}
	return fmt.Errorf("plaud: refusing redirect to disallowed host %q", req.URL.Hostname())
}

func devHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: devCheckRedirect}
}

// DevTokenFile mirrors ~/.plaud/tokens-mcp.json, written by the official
// `npx @plaud-ai/mcp login` (driven by tools/plaud-mcp-login.mjs).
type DevTokenFile struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    int64  `json:"expires_at"` // epoch MILLISECONDS
}

// DevClient talks to the Plaud developer API using the OAuth access token minted
// by the official MCP login. This is the durable, SSO-native capture path, no
// localStorage scraping, no ephemeral browser token, no consumer API.
type DevClient struct {
	token        string
	refreshToken string
	tokenPath    string // ~/.plaud/tokens-mcp.json, for persisting a refresh
	base         string // API base; overridable in tests
	httpClient   *http.Client
}

// NewDevClientFromFile loads the OAuth token from ~/.plaud/tokens-mcp.json and
// returns a client. The access token lives ~24h; when at/near expiry it is
// AUTO-REFRESHED via the long-lived refresh_token (hands-off, no re-login) and
// the refreshed token is persisted back to the file.
func NewDevClientFromFile(path string) (*DevClient, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plaud: read %s: %w, run: node tools/plaud-mcp-login.mjs", path, err)
	}
	var t DevTokenFile
	if json.Unmarshal(data, &t) != nil || t.AccessToken == "" {
		return nil, fmt.Errorf("plaud: no access_token in %s, run: node tools/plaud-mcp-login.mjs", path)
	}
	expired := t.ExpiresAt > 0 && time.Now().After(time.UnixMilli(t.ExpiresAt))
	nearExpiry := t.ExpiresAt > 0 && time.Now().After(time.UnixMilli(t.ExpiresAt).Add(-devRefreshMargin))
	switch {
	case nearExpiry && t.RefreshToken != "":
		if nt, rerr := refreshDevToken(devAPIBase, t.RefreshToken); rerr == nil && nt.AccessToken != "" {
			t = nt
			_ = saveDevTokenFile(path, t)
			fmt.Fprintln(os.Stderr, "  [plaud] developer token refreshed (no re-login needed)")
		} else if expired {
			return nil, fmt.Errorf("plaud: developer token expired and refresh failed (%v), re-run: node tools/plaud-mcp-login.mjs", rerr)
		}
	case expired:
		return nil, fmt.Errorf("plaud: developer token expired, re-run: node tools/plaud-mcp-login.mjs")
	}
	return &DevClient{
		token: t.AccessToken, refreshToken: t.RefreshToken, tokenPath: path,
		base: devAPIBase, httpClient: devHTTPClient(90 * time.Second),
	}, nil
}

// refreshDevToken exchanges the refresh_token for a fresh access token via the
// public-client (PKCE, no secret) grant. Returns the new token set.
func refreshDevToken(base, refreshToken string) (DevTokenFile, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {devOAuthClientID},
	}.Encode()
	req, err := http.NewRequest("POST", base+"/oauth/third-party/access-token/refresh", strings.NewReader(form))
	if err != nil {
		return DevTokenFile{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := devHTTPClient(30 * time.Second).Do(req)
	if err != nil {
		return DevTokenFile{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &r) != nil || r.AccessToken == "" {
		return DevTokenFile{}, fmt.Errorf("HTTP %d: %.150s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	out := DevTokenFile{AccessToken: r.AccessToken, RefreshToken: r.RefreshToken, TokenType: "bearer"}
	if out.RefreshToken == "" {
		out.RefreshToken = refreshToken // reuse if the server didn't rotate it
	}
	if exp := jwtExpiry(r.AccessToken); !exp.IsZero() {
		out.ExpiresAt = exp.UnixMilli()
	} else if r.ExpiresIn > 0 {
		out.ExpiresAt = time.Now().Add(time.Duration(r.ExpiresIn) * time.Second).UnixMilli()
	}
	return out, nil
}

// saveDevTokenFile writes the token set back to ~/.plaud/tokens-mcp.json (0600)
// ATOMICALLY (temp + rename) so a concurrent reader never sees a truncated file
// and a crash mid-write can't lose the durable refresh token.
func saveDevTokenFile(path string, t DevTokenFile) error {
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AccessToken returns the bearer this client uses, for deriving the shared
// plaud-sync account id (DeriveAccountID) so status/register are self-consistent.
func (c *DevClient) AccessToken() string { return c.token }

func (c *DevClient) doGet(path string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", c.base+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return body, resp.StatusCode, nil
}

func (c *DevClient) get(path string) ([]byte, error) {
	body, status, err := c.doGet(path)
	if err != nil {
		return nil, err
	}
	// Auto-refresh on rejection, then retry once (hands-off).
	if (status == 401 || status == 403) && c.refreshToken != "" {
		if nt, rerr := refreshDevToken(c.base, c.refreshToken); rerr == nil && nt.AccessToken != "" {
			c.token, c.refreshToken = nt.AccessToken, nt.RefreshToken
			if c.tokenPath != "" {
				_ = saveDevTokenFile(c.tokenPath, nt)
			}
			body, status, err = c.doGet(path)
			if err != nil {
				return nil, err
			}
		}
	}
	switch status {
	case 200:
		return body, nil
	case 401, 403:
		return nil, fmt.Errorf("plaud: developer token rejected (HTTP %d), re-run: node tools/plaud-mcp-login.mjs", status)
	default:
		return nil, fmt.Errorf("plaud: developer API %s: HTTP %d: %.200s", path, status, strings.TrimSpace(string(body)))
	}
}

// DevRecording is one item in the developer /files list.
type DevRecording struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	CreatedAt    string `json:"created_at"`
	StartAt      string `json:"start_at"`
	Duration     int64  `json:"duration"` // milliseconds
	SerialNumber string `json:"serial_number"`
}

// ParseDevTime parses a developer-API timestamp (start_at, created_at) and
// reports whether it could.
//
// The zone-less layout is deliberate and correct: Plaud emits UTC WITHOUT a
// suffix, "2026-09-03T13:44:14" is a recording made at 15:44 Berlin time during
// CEST, and time.Parse assigns UTC to a layout that carries no zone, so the
// returned INSTANT is right. Only its rendering zone is still open: every caller
// that shows the value to a human, or writes it into a zone-less field such as
// ER1's current_time, must call .Local() first. RFC3339 stays in the list so a
// future Plaud release that does add an offset keeps working. FR-0095.
func ParseDevTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// StartedAtLocal returns the recording's true start time in the machine's local
// zone. The moment the button was pressed, not the upload or the transcription.
func (r DevRecording) StartedAtLocal() (time.Time, bool) {
	t, ok := ParseDevTime(r.StartAt)
	if !ok {
		return time.Time{}, false
	}
	return t.Local(), true
}

// ListRecordings returns ALL of the user's recordings from the developer API,
// paginating (the endpoint returns a default page of ~20).
func (c *DevClient) ListRecordings() ([]DevRecording, error) {
	const pageSize = 100 // server caps page_size at 100
	var all []DevRecording
	seen := make(map[string]bool)
	for page := 1; page <= 1000; page++ {
		body, err := c.get(fmt.Sprintf("/open/third-party/files/?page=%d&page_size=%d", page, pageSize))
		if err != nil {
			return nil, fmt.Errorf("list recordings: %w", err)
		}
		var r struct {
			Data []DevRecording `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("list recordings: parse: %w", err)
		}
		added := 0
		for _, rec := range r.Data {
			if !seen[rec.ID] { // guard against a server that ignores skip
				seen[rec.ID] = true
				all = append(all, rec)
				added++
			}
		}
		if len(r.Data) < pageSize || added == 0 {
			break
		}
	}
	return all, nil
}

// DevDetail is the /files/:id response: metadata + a presigned MP3 URL + the
// transcript (source_list) and AI notes (note_list).
type DevDetail struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	PresignedURL string            `json:"presigned_url"`
	StartAt      string            `json:"start_at"`
	Duration     int64             `json:"duration"`
	SourceList   []json.RawMessage `json:"source_list"`
	NoteList     []json.RawMessage `json:"note_list"`
}

// GetDetail fetches a single recording's detail (audio URL + transcript + notes).
func (c *DevClient) GetDetail(id string) (*DevDetail, error) {
	if err := ValidateDocID(id); err != nil {
		return nil, err
	}
	body, err := c.get("/open/third-party/files/" + id)
	if err != nil {
		return nil, fmt.Errorf("get detail %s: %w", id, err)
	}
	var d DevDetail
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("get detail %s: parse: %w", id, err)
	}
	return &d, nil
}

// devSegment is one transcript segment inside a source_list item's data_content.
type devSegment struct {
	Content string `json:"content"`
	Speaker string `json:"speaker"`
}

// TranscriptText renders the transcript from source_list. Each source_list item
// carries a `data_content` field that is itself a JSON array of segments
// [{content, speaker, start_time}]; the segments are joined with speaker labels.
func (d *DevDetail) TranscriptText() string { return renderDataContent(d.SourceList, true) }

// NotesText renders the AI notes/summary from note_list, whose items carry a
// `data_content` markdown string.
func (d *DevDetail) NotesText() string { return renderDataContent(d.NoteList, false) }

// renderDataContent extracts readable text from Plaud's source_list / note_list.
// Each item's `data_content` is EITHER a JSON array of transcript segments
// (rendered with speaker labels when withSpeakers) OR a markdown/plain string.
// Falls back to a direct text field if the item has no data_content.
func renderDataContent(items []json.RawMessage, withSpeakers bool) string {
	var b strings.Builder
	for _, raw := range items {
		var item struct {
			DataContent string `json:"data_content"`
		}
		if json.Unmarshal(raw, &item) != nil || strings.TrimSpace(item.DataContent) == "" {
			if s := firstTextField(raw); s != "" {
				b.WriteString(s + "\n")
			}
			continue
		}
		var segs []devSegment
		if json.Unmarshal([]byte(item.DataContent), &segs) == nil && len(segs) > 0 {
			last := ""
			for _, s := range segs {
				if strings.TrimSpace(s.Content) == "" {
					continue
				}
				if withSpeakers && s.Speaker != "" && s.Speaker != last {
					b.WriteString("\n" + s.Speaker + ": ")
					last = s.Speaker
				}
				b.WriteString(s.Content + " ")
			}
			b.WriteString("\n")
		} else {
			b.WriteString(item.DataContent + "\n\n") // markdown / plain
		}
	}
	return strings.TrimSpace(b.String())
}

// firstTextField returns the first text-like string field of a JSON object
// (fallback for shapes without data_content).
func firstTextField(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	for _, k := range []string{"text", "content", "asr_text", "transcript", "value", "summary", "markdown"} {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// DownloadAudio fetches the MP3 from the presigned S3 URL (no auth header; the
// URL is pre-signed). The host is validated against the S3 allowlist.
func (c *DevClient) DownloadAudio(presignedURL string) ([]byte, error) {
	if !isAllowedS3URL(presignedURL) {
		return nil, fmt.Errorf("plaud: audio URL is not an allowed https S3 host")
	}
	resp, err := c.httpClient.Get(presignedURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("plaud: audio download HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20)) // 256 MB cap
}
