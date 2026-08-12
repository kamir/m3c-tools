package plaud

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// captureAndValidateAuthHeader reads the live Authorization header off an
// api.plaud.ai request (by reloading a logged-in plaud.ai tab and watching its
// network traffic via CDP), then validates it against the API. This is the
// SSO-safe token path: it works for Google/Apple-SSO accounts whose bearer never
// lands in localStorage, because it reads exactly what the web app sends on the
// wire — independent of where Plaud stores the token.
func captureAndValidateAuthHeader(wsURL string) (string, error) {
	fmt.Fprintln(os.Stderr, "  [plaud] token not in browser storage — capturing the live "+
		"api.plaud.ai Authorization header (reloading the tab, ~up to 15s)...")

	raw, err := cdpCaptureAuthHeader(wsURL, 15*time.Second)
	if err != nil {
		return "", err
	}

	tok := sanitizePlaudToken(raw)
	tok = strings.TrimSpace(strings.TrimPrefix(tok, "Bearer "))
	tok = sanitizePlaudToken(tok)
	if tok == "" || hasControlChars(tok) {
		return "", fmt.Errorf("captured Authorization header was empty or malformed")
	}

	cfg := LoadConfig()
	if !isAllowedPlaudDomain(cfg.APIURL) {
		return "", fmt.Errorf("plaud: API base is not an https *.plaud.ai host")
	}
	ok, err := NewClient(cfg, tok).TokenAuthenticates()
	if err != nil {
		return "", fmt.Errorf("captured token could not be validated: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("captured token was rejected by the API")
	}
	fmt.Fprintln(os.Stderr, "  [plaud] token captured from live network traffic (SSO-safe) and validated")
	return tok, nil
}

// cdpCaptureAuthHeader enables CDP network events on the tab, reloads the page so
// the SPA re-issues its api.plaud.ai calls, and returns the Authorization header
// value from the first such request seen. Returns an error if none appears
// within timeout.
func cdpCaptureAuthHeader(wsURL string, timeout time.Duration) (string, error) {
	conn, err := cdpDial(wsURL)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	for _, cmd := range []string{
		`{"id":1,"method":"Network.enable"}`,
		`{"id":2,"method":"Page.enable"}`,
		`{"id":3,"method":"Page.reload","params":{"ignoreCache":true}}`,
	} {
		if _, err := conn.Write(cdpFrame(cmd)); err != nil {
			return "", fmt.Errorf("cdp send: %w", err)
		}
	}

	// The read deadline bounds the whole capture: once it passes, cdpReadMessage
	// returns an error and the loop ends.
	debug := os.Getenv("M3C_PLAUD_DEBUG") != ""
	plaudReqs := make(map[string]bool) // requestId -> request targets a *.plaud.ai host
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		msg, err := cdpReadMessage(conn)
		if err != nil {
			return "", fmt.Errorf("no api.plaud.ai request with an Authorization header seen within %s", timeout)
		}
		if auth := authHeaderFromCDPEvent(msg, plaudReqs, debug); auth != "" {
			return auth, nil
		}
	}
}

// authHeaderFromCDPEvent inspects one CDP message for the bearer. The
// Authorization header can arrive in EITHER `Network.requestWillBeSent`
// (headers the page set on the fetch) OR — for headers added lower in the stack
// — only in `Network.requestWillBeSentExtraInfo`, which carries the real on-wire
// headers but no URL. So we remember which requestIds target *.plaud.ai from the
// first event, and match the header from either. `plaudReqs` is shared across
// calls to correlate the two events by requestId.
func authHeaderFromCDPEvent(msg string, plaudReqs map[string]bool, debug bool) string {
	var m struct {
		Method string `json:"method"`
		Params struct {
			RequestID string `json:"requestId"`
			Request   struct {
				URL     string            `json:"url"`
				Headers map[string]string `json:"headers"`
			} `json:"request"`
			Headers map[string]string `json:"headers"` // requestWillBeSentExtraInfo
		} `json:"params"`
	}
	if json.Unmarshal([]byte(msg), &m) != nil {
		return ""
	}
	switch m.Method {
	case "Network.requestWillBeSent":
		if debug {
			// Log EVERY request the captured tab makes (origin only, secret-safe) so
			// a failed capture shows whether the tab is the logged-in one and where
			// its API calls go.
			fmt.Fprintf(os.Stderr, "  [plaud-debug]   req %s auth=%v\n",
				plaudURLOrigin(m.Params.Request.URL), lookupAuthHeader(m.Params.Request.Headers) != "")
		}
		if !isPlaudHost(m.Params.Request.URL) {
			return ""
		}
		plaudReqs[m.Params.RequestID] = true
		return lookupAuthHeader(m.Params.Request.Headers)
	case "Network.requestWillBeSentExtraInfo":
		if !plaudReqs[m.Params.RequestID] {
			return ""
		}
		return lookupAuthHeader(m.Params.Headers)
	}
	return ""
}

// lookupAuthHeader returns a non-empty Authorization header value from a CDP
// headers map (header names keep their original case; match insensitively).
func lookupAuthHeader(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "authorization") && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// isPlaudHost reports whether rawURL's host is plaud.ai or a subdomain of it.
func isPlaudHost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "plaud.ai" || strings.HasSuffix(h, ".plaud.ai")
}

// cdpReadMessage reads one complete CDP message from a WebSocket, reassembling
// continuation frames and skipping control frames. Server→client frames are
// unmasked (RFC 6455 §5.1); this reader handles masked frames too, for safety.
func cdpReadMessage(conn net.Conn) (string, error) {
	var payload []byte
	for {
		fin, opcode, data, err := cdpReadFrame(conn)
		if err != nil {
			return "", err
		}
		switch opcode {
		case 0x0, 0x1, 0x2: // continuation / text / binary
			payload = append(payload, data...)
			if fin {
				return string(payload), nil
			}
		case 0x8: // close
			return "", fmt.Errorf("websocket closed")
		case 0x9, 0xA: // ping / pong — ignore
		default:
			// Unknown opcode; ignore its payload and keep reading.
		}
	}
}

// cdpReadFrame reads a single WebSocket frame header + payload.
func cdpReadFrame(conn net.Conn) (fin bool, opcode byte, payload []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	n := int(hdr[1] & 0x7F)
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(conn, ext); err != nil {
			return
		}
		n = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(conn, ext); err != nil {
			return
		}
		n = 0
		for _, b := range ext {
			n = n<<8 | int(b)
		}
	}
	if n < 0 || n > 16<<20 { // sanity cap: 16 MB
		return fin, opcode, nil, fmt.Errorf("cdp frame too large: %d", n)
	}
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err = io.ReadFull(conn, mask); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}
