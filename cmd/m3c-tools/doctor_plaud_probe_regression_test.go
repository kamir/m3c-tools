package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/diag"
)

func TestDoctorPlaudToken_MissingStatusRemainsUnverified(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"msg":"upstream unavailable"}`, `{"status":null}`} {
		t.Run(body, func(t *testing.T) {
			setupDoctorPlaudFake(t, plaudStatusHandler(body), false)
			c := plaudTokenCheck(t)
			t.Logf("body=%s status=%v detail=%q", body, c.Status, c.Detail)
			if c.Status == diag.OK {
				t.Error("missing explicit Plaud status must not authenticate")
			}
		})
	}
}

type deadlineProbeTransport struct {
	next      http.RoundTripper
	remaining time.Duration
}

func (d *deadlineProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if deadline, ok := r.Context().Deadline(); ok {
		d.remaining = time.Until(deadline)
	}
	return d.next.RoundTrip(r)
}
func TestDoctorPlaudToken_ProbeHasDiagnosticDeadline(t *testing.T) {
	ft := setupDoctorPlaudFake(t, plaudStatusHandler(`{"status":0}`), false)
	d := &deadlineProbeTransport{next: ft}
	http.DefaultTransport = d
	c := plaudTokenCheck(t)
	t.Logf("status=%v request budget=%s", c.Status, d.remaining)
	if d.remaining <= 0 || d.remaining > 5*time.Second {
		t.Errorf("doctor request budget %s exceeds diagnostic 5s allowance; QA wrapper is 40s", d.remaining)
	}
}
