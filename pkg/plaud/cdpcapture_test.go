package plaud

import (
	"net"
	"testing"
	"time"
)

func TestAuthHeaderFromCDPEvent(t *testing.T) {
	cases := []struct {
		name, msg, want string
	}{
		{
			"api request with Authorization",
			`{"method":"Network.requestWillBeSent","params":{"request":{"url":"https://api.plaud.ai/file/simple/web","headers":{"Authorization":"Bearer eyJ.a.b"}}}}`,
			"Bearer eyJ.a.b",
		},
		{
			"lowercase header name",
			`{"method":"Network.requestWillBeSent","params":{"request":{"url":"https://api-euc1.plaud.ai/x","headers":{"authorization":"Bearer eu.tok"}}}}`,
			"Bearer eu.tok",
		},
		{
			"wrong method ignored",
			`{"method":"Network.responseReceived","params":{"request":{"url":"https://api.plaud.ai/x","headers":{"Authorization":"Bearer z"}}}}`,
			"",
		},
		{
			"non-plaud host ignored",
			`{"method":"Network.requestWillBeSent","params":{"request":{"url":"https://evil.example/x","headers":{"Authorization":"Bearer z"}}}}`,
			"",
		},
		{
			"no auth header",
			`{"method":"Network.requestWillBeSent","params":{"request":{"url":"https://web.plaud.ai/home","headers":{"Accept":"application/json"}}}}`,
			"",
		},
		{"garbage", `not json`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := authHeaderFromCDPEvent(c.msg, make(map[string]bool), false); got != c.want {
				t.Errorf("authHeaderFromCDPEvent = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAuthHeaderFromCDPEvent_ExtraInfoCorrelation(t *testing.T) {
	reqs := make(map[string]bool)
	// The initial event marks the requestId as a plaud request but carries no auth.
	pre := `{"method":"Network.requestWillBeSent","params":{"requestId":"R1","request":{"url":"https://api.plaud.ai/file/simple/web","headers":{}}}}`
	if got := authHeaderFromCDPEvent(pre, reqs, false); got != "" {
		t.Fatalf("pre-event should yield no auth, got %q", got)
	}
	// The extraInfo event (no URL) carries the real Authorization; correlated by requestId.
	extra := `{"method":"Network.requestWillBeSentExtraInfo","params":{"requestId":"R1","headers":{"authorization":"Bearer real.tok"}}}`
	if got := authHeaderFromCDPEvent(extra, reqs, false); got != "Bearer real.tok" {
		t.Errorf("extraInfo correlation failed, got %q", got)
	}
	// An extraInfo for an UNKNOWN requestId must be ignored (could be a non-plaud request).
	orphan := `{"method":"Network.requestWillBeSentExtraInfo","params":{"requestId":"R2","headers":{"authorization":"Bearer other"}}}`
	if got := authHeaderFromCDPEvent(orphan, reqs, false); got != "" {
		t.Errorf("orphan extraInfo should be ignored, got %q", got)
	}
}

func TestIsPlaudHost(t *testing.T) {
	cases := map[string]bool{
		"https://api.plaud.ai/x":      true,
		"https://web.plaud.ai/":       true,
		"https://api-euc1.plaud.ai/y": true,
		"https://plaud.ai":            true,
		"https://evilplaud.ai/x":      false,
		"https://plaud.ai.evil.com/x": false,
		"https://evil.example/x":      false,
	}
	for u, want := range cases {
		if got := isPlaudHost(u); got != want {
			t.Errorf("isPlaudHost(%q) = %v, want %v", u, got, want)
		}
	}
}

// buildServerFrame builds an unmasked RFC-6455 frame (as Chrome sends to us).
func buildServerFrame(fin bool, opcode byte, payload []byte) []byte {
	b := []byte{opcode}
	if fin {
		b[0] |= 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		b = append(b, byte(n))
	case n < 65536:
		b = append(b, 126, byte(n>>8), byte(n))
	default:
		b = append(b, 127)
		ext := make([]byte, 8)
		for i, v := 7, n; i >= 0; i-- {
			ext[i] = byte(v)
			v >>= 8
		}
		b = append(b, ext...)
	}
	return append(b, payload...)
}

func TestCDPReadMessage_ReassemblesAndSkipsControl(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))

	go func() {
		c2.Write(buildServerFrame(true, 0x9, []byte("ping")))  // control frame → skipped
		c2.Write(buildServerFrame(false, 0x1, []byte("he")))   // text, not final
		c2.Write(buildServerFrame(true, 0x0, []byte("llo")))   // continuation, final
	}()

	msg, err := cdpReadMessage(c1)
	if err != nil {
		t.Fatalf("cdpReadMessage: %v", err)
	}
	if msg != "hello" {
		t.Errorf("reassembled message = %q, want %q", msg, "hello")
	}
}

func TestCDPReadMessage_ExtendedLength(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))

	big := make([]byte, 300) // forces the 16-bit extended length path
	for i := range big {
		big[i] = 'x'
	}
	go func() { c2.Write(buildServerFrame(true, 0x1, big)) }()

	msg, err := cdpReadMessage(c1)
	if err != nil {
		t.Fatalf("cdpReadMessage: %v", err)
	}
	if len(msg) != 300 {
		t.Errorf("len = %d, want 300", len(msg))
	}
}
