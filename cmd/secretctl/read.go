package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Reading a value out of a holder. Every function here returns a Secret, never
// a string, so a value cannot reach an output stream by accident.

// ErrAbsent says the holder was REACHED and carries nothing. A place that holds
// no value is a finding, not a failure.
type ErrAbsent struct{ Where string }

func (e ErrAbsent) Error() string { return "no value at " + e.Where }

// ErrUnreachable says the question could not be asked at all. It exists as its
// own type because conflating it with ErrAbsent is the single most dangerous
// mistake an inventory can make: during a rotation, "holds no value" reads as
// "nothing to do here", and the place then keeps the compromised value while
// the table says the rotation is complete.
//
// Measured on 2026-09-15: two consecutive runs disagreed about the same four
// places on macpro2, because the second run could not open an ssh connection
// and every transport error was being mapped to ErrAbsent. Same shape as
// BUG-0437, where an unknown registry context produced an empty list instead
// of an error. An unanswerable question must never be reported as a negative
// answer.
type ErrUnreachable struct {
	Where  string
	Reason string
}

func (e ErrUnreachable) Error() string {
	return "could not reach " + e.Where + ": " + e.Reason
}

// ReadHolder fetches the value one holder currently carries.
func ReadHolder(h Holder) (Secret, error) {
	switch h.Kind {
	case "macos-keychain":
		return readKeychain(h)
	case "file":
		return readFile(h)
	case "cloud-run":
		// A Cloud Run service does not hand its env back, and asking would
		// need deploy-level rights. What CAN be established is which secret
		// VERSION the running revision is bound to, and that is what the
		// inventory reports for this kind.
		return "", fmt.Errorf("cloud-run holders are checked by bound version, not by value")
	}
	return "", fmt.Errorf("unknown holder kind %q", h.Kind)
}

// capture runs a command locally or over ssh and returns its stdout.
// Named capture, not run: main.run is the command dispatcher, and two
// functions of the same name in one package is a compile error waiting for
// the second one.
func capture(host string, name string, args ...string) (string, error) {
	var cmd *exec.Cmd
	if host == "" {
		cmd = exec.Command(name, args...)
	} else {
		// The remote command is assembled here rather than interpolated into a
		// shell string, so a holder's fields cannot become shell syntax.
		remote := append([]string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, name}, args...)
		cmd = exec.Command("ssh", remote...)
	}
	out, err := cmd.Output()
	return strings.TrimRight(string(out), "\n"), err
}

func readKeychain(h Holder) (Secret, error) {
	host := ""
	if !h.IsLocal() {
		host = h.Host
	}
	// Existence and readability are two different questions, and conflating
	// them cost a wrong report on 2026-09-15: `find-generic-password` without
	// -w succeeds for an entry that -w then refuses to hand over, because a
	// non-interactive ssh session cannot unlock the keychain. "No value here"
	// and "this machine will not give it to me from here" are different
	// findings and must not share a word.
	if _, existsErr := capture(host, "security", "find-generic-password", "-s", h.Service); existsErr != nil {
		if host != "" && isTransportFailure(existsErr) {
			return "", ErrUnreachable{Where: h.ID, Reason: "ssh to " + host + " failed"}
		}
		return "", ErrAbsent{Where: h.ID}
	}
	out, err := capture(host, "security", "find-generic-password", "-s", h.Service, "-w")
	if err != nil || out == "" {
		if host != "" {
			return "", fmt.Errorf("keychain entry exists on %s but will not unlock over ssh; "+
				"run the check on that machine", host)
		}
		return "", fmt.Errorf("keychain entry exists but will not unlock")
	}
	return Secret(out), nil
}

func readFile(h Holder) (Secret, error) {
	host := ""
	if !h.IsLocal() {
		host = h.Host
	}
	path := h.Path
	if strings.HasPrefix(path, "~/") {
		if host == "" {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, path[2:])
		} else {
			// Let the remote shell expand it; ssh runs a login shell.
			path = "$HOME/" + path[2:]
		}
	}
	// grep, not cat: the whole file must not travel just because one line is
	// wanted, and a file may hold more than one secret.
	out, err := capture(host, "grep", "-m1", "^"+h.Key+"=", path)
	if err != nil {
		// grep says 1 when it found nothing and 2 when it could not read the
		// file; ssh says 255 when it could not connect at all. Only the first
		// is an absence.
		if host != "" && isTransportFailure(err) {
			return "", ErrUnreachable{Where: h.ID, Reason: "ssh to " + host + " failed"}
		}
		return "", ErrAbsent{Where: h.ID}
	}
	if out == "" {
		return "", ErrAbsent{Where: h.ID}
	}
	_, value, ok := strings.Cut(out, "=")
	if !ok {
		return "", ErrAbsent{Where: h.ID}
	}
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if value == "" {
		return "", ErrAbsent{Where: h.ID}
	}
	return Secret(value), nil
}

// ReadSource fetches the currently active value from the authoritative store.
func ReadSource(s Source) (Secret, error) {
	if s.Kind != "gcp-secret-manager" {
		return "", fmt.Errorf("unknown source kind %q", s.Kind)
	}
	out, err := capture("", "gcloud", "secrets", "versions", "access", "latest",
		"--secret="+s.Secret, "--project="+s.Project)
	if err != nil {
		return "", fmt.Errorf("source %s/%s: %w", s.Project, s.Secret, err)
	}
	if out == "" {
		return "", ErrAbsent{Where: s.Secret}
	}
	return Secret(out), nil
}

// BoundVersion reports which secret version a Cloud Run service binds its env
// var to. It parses JSON rather than scanning a flattened line: the first draft
// looked for "any field containing a colon and a dash" and happily reported a
// service URL and an unrelated secret reference as if they were versions. A
// parser that cannot fail loudly reports nonsense confidently.
func BoundVersion(h Holder) (string, error) {
	out, err := capture("", "gcloud", "run", "services", "describe", h.Service_,
		"--project="+h.Project, "--region="+h.Region, "--format=json")
	if err != nil {
		return "", err
	}
	var doc struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Env []struct {
							Name      string `json:"name"`
							ValueFrom struct {
								SecretKeyRef struct {
									Name string `json:"name"`
									Key  string `json:"key"`
								} `json:"secretKeyRef"`
							} `json:"valueFrom"`
						} `json:"env"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return "", fmt.Errorf("describe %s: %w", h.Service_, err)
	}
	for _, c := range doc.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name != h.Env {
				continue
			}
			ref := e.ValueFrom.SecretKeyRef
			if ref.Name == "" {
				return "", fmt.Errorf("%s binds %s, but not to a secret", h.Service_, h.Env)
			}
			return ref.Name + ":" + ref.Key, nil
		}
	}
	return "", ErrAbsent{Where: h.ID}
}

// Probe asks a service whether a value is accepted right now. It returns the
// status code and nothing else.
//
// In-process HTTP, deliberately NOT a curl subprocess. A value handed to curl
// as `-H "X-API-KEY: ..."` sits in that process argv and is readable by every
// `ps` on the machine for as long as the request runs. The tool that must never
// print a secret must not hand it to a process table either, and the first
// draft of this function did exactly that.
func (p Probe) Ask(value Secret) (int, error) {
	if p.Kind != "http" {
		return 0, fmt.Errorf("unknown probe kind %q", p.Kind)
	}
	req, err := http.NewRequest(http.MethodGet, p.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set(p.Header, value.Reveal())
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// The URL may carry a query; the value never does, but an error string
		// from net/http repeats the request URL, so it is not passed through
		// verbatim.
		return 0, fmt.Errorf("probe %s: request failed", p.URL)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// isTransportFailure reports whether an error is ssh failing to connect rather
// than the remote command answering "no".
//
// ssh exits 255 for its own failures and passes the remote exit code through
// otherwise. grep answers 1 for "no match" and 2 for "cannot read", both of
// which are real answers from a machine that was reached.
func isTransportFailure(err error) bool {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode() == 255
	}
	// Not an ExitError at all: the process could not even be started.
	return true
}
