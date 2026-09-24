package linux

import (
	"context"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// These tests hold the seam between the redactor and the line oriented
// parsers of this package. A capture run as root on Ubuntu 22.04 lost the
// root account because the home path marker carried a colon: line 1 of
// getent passwd became "root:x:0:0:root:[REDACTED:home_path]:/bin/bash",
// eight colon separated fields instead of seven, the parser refused the
// record, and the bundle held 54 user artifacts without device/user/0.

// invRedactedRun runs a probe the way invRun does, with a redactor that also
// removes homeRoot, which is what the capture engine builds (DefaultRedactor).
func invRedactedRun(t *testing.T, p probe.Probe, runner probe.CommandRunner, homeRoot string) (trustfreeze.ProbeResult, []probe.EvidenceItem) {
	t.Helper()
	red, err := redact.New(redact.WithLiteral(homeRoot, "home_path"))
	if err != nil {
		t.Fatalf("redactor for %q: %v", homeRoot, err)
	}
	ev := probe.NewEvidenceBuffer(p.Descriptor().ID, probe.Limits{})
	host := probe.HostContext{
		GOOS: "linux", GOARCH: "amd64",
		Hostname:  func() (string, error) { return "host-a.example", nil },
		Files:     probe.FakeFiles{},
		Runner:    probe.NewRecordingRunner(runner, probe.Limits{}, red),
		Clock:     trustfreeze.FixedClock{T: invTestTime},
		Privilege: probe.PrivilegeElevated,
	}
	ctx := context.Background()
	support := p.Support(ctx, host)
	if !support.Available {
		t.Fatalf("probe %s is not available: %s (%s)", p.Descriptor().ID, support.Status, support.Reason)
	}
	res := p.Collect(ctx, probe.CollectContext{
		HostContext: host,
		ProbeID:     p.Descriptor().ID,
		Redactor:    red,
		Limits:      probe.Limits{},
		Evidence:    ev,
		Support:     support,
	})
	return res, ev.Close()
}

// TestUsersProbeKeepsRootWhenHomeIsRedacted is the measured defect, in a
// test: an elevated capture whose home root is /root redacts the home field
// of line 1 of getent passwd, and the account must still be recorded.
func TestUsersProbeKeepsRootWhenHomeIsRedacted(t *testing.T) {
	res, _ := invRedactedRun(t, NewUsersProbe(), invUsersRunner(t), "/root")
	if w, ok := invWarning(res, invDiagRecordUnparsed); ok {
		t.Fatalf("a redacted record was refused by the parser: %s", w.Message)
	}
	invWantNoWarning(t, res, usrDiagRootAccountMissing)
	root := invArtifact(t, res, ArtifactUserPrefix+"0")
	invWantAttr(t, root, "name", "root")
	invWantAttr(t, root, "shell", "/bin/bash")
	// The home path is gone, the record is not.
	if got := root.Attributes["home"]; got != redact.Marker("home_path") {
		t.Fatalf("root home attribute %q, want the home path marker", got)
	}
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s (%s), want captured", res.Status, res.Reason)
	}
}

// TestParsersSurviveTheReplacementMarker feeds every line oriented parser of
// this package a record in which the redactor really replaced one value, and
// requires the record to keep its field count. The marker is produced by the
// redactor itself, not written out by hand, so the test measures the shipped
// replacement and not a copy of it.
func TestParsersSurviveTheReplacementMarker(t *testing.T) {
	// The values a redactor removes from these records: a home path, a
	// member name, a package version and a process name. Each one stands in
	// a different field of a different format.
	redactValue := func(t *testing.T, line, value string) string {
		t.Helper()
		r, err := redact.New(redact.WithLiteral(value, "home_path"))
		if err != nil {
			t.Fatalf("redactor for %q: %v", value, err)
		}
		out, _, err := r.RedactString(context.Background(), line)
		if err != nil {
			t.Fatalf("RedactString: %v", err)
		}
		if !strings.Contains(out, redact.Marker("home_path")) {
			t.Fatalf("the redactor did not replace %q in %q", value, line)
		}
		return out
	}

	t.Run("getent passwd", func(t *testing.T) {
		line := redactValue(t, "root:x:0:0:root:/root:/bin/bash", "/root")
		users, issues := ParseGetentPasswd([]byte(line + "\n"))
		if len(issues) != 0 {
			t.Fatalf("%q: issues %+v", line, issues)
		}
		if len(users) != 1 || users[0].Name != "root" || users[0].UID != 0 || users[0].Shell != "/bin/bash" {
			t.Fatalf("%q parsed as %+v", line, users)
		}
	})

	t.Run("getent group", func(t *testing.T) {
		line := redactValue(t, "sudo:x:27:alice,deploy", "deploy")
		groups, issues := ParseGetentGroup([]byte(line + "\n"))
		if len(issues) != 0 {
			t.Fatalf("%q: issues %+v", line, issues)
		}
		if len(groups) != 1 || groups[0].Name != "sudo" || groups[0].GID != 27 || len(groups[0].Members) != 2 {
			t.Fatalf("%q parsed as %+v", line, groups)
		}
	})

	t.Run("id", func(t *testing.T) {
		line := redactValue(t, "uid=1000(alice) gid=1000(alice) groups=1000(alice),27(sudo)", "alice")
		info, err := ParseID([]byte(line + "\n"))
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if info.UID != 1000 || info.GID != 1000 || len(info.Groups) != 2 {
			t.Fatalf("%q parsed as %+v", line, info)
		}
	})

	t.Run("dpkg-query", func(t *testing.T) {
		line := redactValue(t, "openssh-server\t1:9.6p1-3ubuntu13\tamd64\tii ", "1:9.6p1-3ubuntu13")
		pkgs, issues := ParseDpkgQuery([]byte(line + "\n"))
		if len(issues) != 0 {
			t.Fatalf("%q: issues %+v", line, issues)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "openssh-server" || pkgs[0].Architecture != "amd64" {
			t.Fatalf("%q parsed as %+v", line, pkgs)
		}
	})

	t.Run("ss", func(t *testing.T) {
		line := redactValue(t, `tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))`, "sshd")
		ls, diags := ParseSSListeners([]byte(line + "\n"))
		if len(diags) != 0 {
			t.Fatalf("%q: diagnostics %+v", line, diags)
		}
		if len(ls) != 1 || ls[0].Port != "22" || ls[0].Address != "0.0.0.0" || len(ls[0].Processes) != 1 {
			t.Fatalf("%q parsed as %+v", line, ls)
		}
	})

	t.Run("docker ps", func(t *testing.T) {
		line := redactValue(t, "abc123\tnginx:1.25\tweb\trunning\tUp 3 days\t0.0.0.0:8080->80/tcp", "nginx:1.25")
		cs, diags := ParseDockerPS([]byte(line + "\n"))
		if len(diags) != 0 {
			t.Fatalf("%q: diagnostics %+v", line, diags)
		}
		if len(cs) != 1 || cs[0].ID != "abc123" || cs[0].State != "running" {
			t.Fatalf("%q parsed as %+v", line, cs)
		}
	})

	// The published port column is split at the LAST colon of the host part,
	// which is the one before the port. A marker standing in the address
	// therefore survived even the colon marker, measured. A marker standing
	// where the port is would not, and it would not be refused either: the
	// split would move and the record would carry a wrong port with no
	// diagnostic. A separator free marker removes both cases.
	t.Run("published ports", func(t *testing.T) {
		column := redactValue(t, "203.0.113.7:8080->80/tcp", "203.0.113.7")
		ports, diags := ParsePublishedPorts(column)
		if len(diags) != 0 {
			t.Fatalf("%q: diagnostics %+v", column, diags)
		}
		if len(ports) != 1 || ports[0].HostPort != "8080" || ports[0].ContainerPort != "80" || ports[0].Proto != "tcp" {
			t.Fatalf("%q parsed as %+v", column, ports)
		}
	})

	t.Run("snap list", func(t *testing.T) {
		line := redactValue(t, "core22 20240111 1122 latest/stable canonical base", "canonical")
		snaps, issues := ParseSnapList([]byte("Name Version Rev Tracking Publisher Notes\n" + line + "\n"))
		if len(issues) != 0 {
			t.Fatalf("%q: issues %+v", line, issues)
		}
		if len(snaps) != 1 || snaps[0].Name != "core22" || snaps[0].Notes != "base" {
			t.Fatalf("%q parsed as %+v", line, snaps)
		}
	})
}

// TestUsersProbeReportsAMissingRootAccount: losing uid 0 is never quiet. When
// getent passwd printed accounts and none of them is uid 0, the probe says so
// by name instead of leaving a reader to count the artifacts.
func TestUsersProbeReportsAMissingRootAccount(t *testing.T) {
	// Constructed output, not a fixture: a passwd database without root.
	r := probe.NewFakeRunner()
	r.Script("getent", []string{"passwd"}, probe.FakeResponse{
		Stdout: []byte("alice:x:1000:1000::/home/alice:/bin/bash\ndeploy:x:1001:1001::/home/deploy:/bin/bash\n"),
	})
	r.Script("getent", []string{"group"}, probe.FakeResponse{Stdout: []byte("alice:x:1000:\ndeploy:x:1001:\n")})
	r.Script("getent", []string{"--version"}, probe.FakeResponse{Stdout: []byte("getent (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39\n")})
	r.Script("id", nil, probe.FakeResponse{Stdout: []byte("uid=1000(alice) gid=1000(alice) groups=1000(alice)\n")})
	r.Script("id", []string{"--version"}, probe.FakeResponse{Stdout: []byte("id (GNU coreutils) 9.4\n")})

	res, _ := invRun(t, NewUsersProbe(), r)
	w := invWantWarning(t, res, usrDiagRootAccountMissing)
	if !strings.Contains(w.Message, "uid 0") {
		t.Fatalf("diagnostic does not name uid 0: %s", w.Message)
	}
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %s, want partial when the root account is absent", res.Status)
	}
	// The fixture host does have root, so the honest run stays quiet.
	ok, _ := invRun(t, NewUsersProbe(), invUsersRunner(t))
	invWantNoWarning(t, ok, usrDiagRootAccountMissing)
}
