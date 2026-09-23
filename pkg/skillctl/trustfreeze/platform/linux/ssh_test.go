package linux

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// Two synthetic ed25519 public keys. They were generated from the seeds
// 0x01... and 0x02... repeated, so the bytes are reproducible and belong to
// nobody. Only the public half appears here; the expected fingerprints are
// pinned, which is what makes this a known answer test of the RFC 4716 SHA256
// form rather than a restatement of the implementation.
const (
	sshTestKeyA            = "AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c"
	sshTestKeyAFingerprint = "SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8"
	sshTestKeyASlug        = "7def39264223a3c5"
	sshTestKeyB            = "AAAAC3NzaC1lZDI1NTE5AAAAIIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"
	sshTestKeyBFingerprint = "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4"
)

// sshFixtureRunner scripts every command linux.ssh runs on the trial host,
// with the argv and the streams testdata/commands.json recorded.
func sshFixtureRunner(t *testing.T) *probe.FakeRunner {
	t.Helper()
	r := probe.NewFakeRunner()
	r.Script(sshdExe, []string{"-V"}, probe.FakeResponse{Stderr: privFixture(t, "ssh/sshd-version.stderr.txt")})
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	r.Script(getentExe, []string{"--version"}, probe.FakeResponse{Stdout: privFixture(t, "users/getent-version.txt")})
	r.Script("ls", []string{"-la", SSHDir}, probe.FakeResponse{Stdout: privFixture(t, "ssh/ls-la-etc-ssh.txt")})
	r.Script("ls", []string{"-la", SSHDConfigDir}, probe.FakeResponse{Stdout: privFixture(t, "ssh/ls-la-sshd-config-d.txt")})
	r.Script(sshdExe, []string{"-T"}, probe.FakeResponse{
		Stderr: privFixture(t, "ssh/sshd-T-unprivileged.stderr.txt"), ExitCode: 1,
	})
	r.Script(getentExe, []string{"passwd"}, probe.FakeResponse{Stdout: privFixture(t, "users/getent-passwd.txt")})
	return r
}

// TestParseSSHDConfigFixture reads the recorded declared state byte for byte.
func TestParseSSHDConfigFixture(t *testing.T) {
	f := ParseSSHDConfig(SSHDConfigPath, privFixture(t, "ssh/sshd_config.txt"))
	if len(f.Issues) != 0 {
		t.Fatalf("issues %+v", f.Issues)
	}
	if f.Comments < 40 {
		t.Fatalf("comment lines %d, want the stock file's comment block", f.Comments)
	}
	d := ResolveSSHD(f.Directives)
	want := map[string]string{
		"passwordauthentication":       "yes",
		"permitemptypasswords":         "yes",
		"kbdinteractiveauthentication": "no",
		"usepam":                       "yes",
		"x11forwarding":                "yes",
	}
	for k, v := range want {
		if d.Values[k] != v {
			t.Fatalf("%s = %q, want %q", k, d.Values[k], v)
		}
	}
	// A commented Match block is a comment, not a conditional block.
	if len(d.Matches) != 0 {
		t.Fatalf("matches %+v, want none", d.Matches)
	}
	// The tab separated Subsystem line keeps both of its arguments.
	if sub := d.Multi["subsystem"]; len(sub) != 1 || !strings.Contains(sub[0], "sftp-server") {
		t.Fatalf("subsystem %+v", sub)
	}
	if env := d.Multi["acceptenv"]; len(env) != 1 || env[0] != "LANG LC_*" {
		t.Fatalf("acceptenv %+v", env)
	}
	// The commented defaults of the stock file are comments: a keyword that is
	// only commented must not appear in the declared state.
	if v, ok := d.Values["permitrootlogin"]; ok {
		t.Fatalf("a commented keyword became declared state: %q", v)
	}
	if got := d.Origin["passwordauthentication"]; got != SSHDConfigPath+":57" {
		t.Fatalf("origin %q", got)
	}
}

// TestResolveSSHDFirstValueWins pins the documented rule: sshd takes the first
// obtained value of a keyword, so a later line does not override it.
func TestResolveSSHDFirstValueWins(t *testing.T) {
	in := "PasswordAuthentication no\nPasswordAuthentication yes\nPort 22\nPort 2222\n"
	d := ResolveSSHD(ParseSSHDConfig("f", []byte(in)).Directives)
	if d.Values["passwordauthentication"] != "no" {
		t.Fatalf("passwordauthentication = %q, want the first value", d.Values["passwordauthentication"])
	}
	if got := strings.Join(d.Multi["port"], ","); got != "22,2222" {
		t.Fatalf("port = %q, want both values in order", got)
	}
}

// TestResolveSSHDKeywordForms covers the spellings sshd accepts.
func TestResolveSSHDKeywordForms(t *testing.T) {
	in := "  MaxAuthTries=3\nUsePAM\t yes\n#PermitRootLogin yes\n\nLogLevel = INFO\n"
	f := ParseSSHDConfig("f", []byte(in))
	d := ResolveSSHD(f.Directives)
	if d.Values["maxauthtries"] != "3" || d.Values["usepam"] != "yes" || d.Values["loglevel"] != "INFO" {
		t.Fatalf("values %+v", d.Values)
	}
	if f.Comments != 1 {
		t.Fatalf("comments %d", f.Comments)
	}
}

// TestResolveSSHDMatchIsNotGlobal: a keyword inside a Match block belongs to
// that block, never to the global declared state.
func TestResolveSSHDMatchIsNotGlobal(t *testing.T) {
	in := "PasswordAuthentication no\n" +
		"Match User alice\n" +
		"    PasswordAuthentication yes\n" +
		"    X11Forwarding yes\n"
	d := ResolveSSHD(ParseSSHDConfig(SSHDConfigPath, []byte(in)).Directives)
	if d.Values["passwordauthentication"] != "no" {
		t.Fatalf("the Match block leaked into the global state: %q", d.Values["passwordauthentication"])
	}
	if len(d.Matches) != 1 {
		t.Fatalf("matches %+v", d.Matches)
	}
	m := d.Matches[0]
	if m.Criteria != "User alice" || m.Line != 2 {
		t.Fatalf("match %+v", m)
	}
	if strings.Join(m.Keywords, ",") != "passwordauthentication,x11forwarding" {
		t.Fatalf("keywords %v", m.Keywords)
	}
}

// TestExpandSSHDIncludes proves the rule that makes the Ubuntu drop-in win:
// the Include stands in the first lines, so its value is the first obtained
// one.
func TestExpandSSHDIncludes(t *testing.T) {
	root := ParseSSHDConfig(SSHDConfigPath, []byte(
		"Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n"))
	drop := ParseSSHDConfig(SSHDConfigDir+"/50-cloud-init.conf", []byte("PasswordAuthentication no\n"))
	other := ParseSSHDConfig(SSHDConfigDir+"/10-first.conf", []byte("PermitRootLogin no\n"))
	avail := map[string]SSHDConfigFile{drop.Path: drop, other.Path: other}
	dirs, diags := ExpandSSHDIncludes(root, avail, sshMaxIncludeDepth)
	if len(diags) != 0 {
		t.Fatalf("diagnostics %+v", diags)
	}
	d := ResolveSSHD(dirs)
	if d.Values["passwordauthentication"] != "no" {
		t.Fatalf("the drop-in did not win: %q", d.Values["passwordauthentication"])
	}
	if d.Origin["passwordauthentication"] != drop.Path+":1" {
		t.Fatalf("origin %q", d.Origin["passwordauthentication"])
	}
	if d.Values["permitrootlogin"] != "no" {
		t.Fatalf("permitrootlogin %q", d.Values["permitrootlogin"])
	}
	// The files are expanded in path order, the way sshd sorts a glob.
	if dirs[0].File != other.Path {
		t.Fatalf("expansion order %q first", dirs[0].File)
	}
}

// TestExpandSSHDIncludesEmptyPattern: an include that matches nothing is
// reported as such, never as a parse failure.
func TestExpandSSHDIncludesEmptyPattern(t *testing.T) {
	root := ParseSSHDConfig(SSHDConfigPath, []byte("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"))
	dirs, diags := ExpandSSHDIncludes(root, map[string]SSHDConfigFile{}, sshMaxIncludeDepth)
	if len(diags) != 1 || diags[0].Code != sshDiagIncludeMatchedNothing {
		t.Fatalf("diagnostics %+v", diags)
	}
	if len(dirs) != 1 || dirs[0].Keyword != "port" {
		t.Fatalf("directives %+v", dirs)
	}
}

// TestExpandSSHDIncludesRelativeAndDepth covers a relative pattern and the
// nesting bound.
func TestExpandSSHDIncludesRelativeAndDepth(t *testing.T) {
	root := ParseSSHDConfig(SSHDConfigPath, []byte("Include sshd_config.d/*.conf\n"))
	nested := ParseSSHDConfig(SSHDConfigDir+"/a.conf", []byte("Include sshd_config.d/b.conf\nPort 22\n"))
	b := ParseSSHDConfig(SSHDConfigDir+"/b.conf", []byte("Port 2222\n"))
	dirs, diags := ExpandSSHDIncludes(root, map[string]SSHDConfigFile{nested.Path: nested, b.Path: b}, sshMaxIncludeDepth)
	if len(diags) != 0 {
		t.Fatalf("diagnostics %+v", diags)
	}
	if got := len(dirs); got != 2 {
		t.Fatalf("directives %+v", dirs)
	}
	// Depth 0 stops before any expansion.
	shallow, diags := ExpandSSHDIncludes(root, map[string]SSHDConfigFile{nested.Path: nested}, 0)
	if len(shallow) != 0 || len(diags) != 1 || diags[0].Code != privDiagRecordUnparsed {
		t.Fatalf("directives %+v diagnostics %+v", shallow, diags)
	}
}

// TestParseAuthorizedKeys pins the fingerprint form and proves that neither
// the key body nor the comment survives the parser (playbook L4).
func TestParseAuthorizedKeys(t *testing.T) {
	in := "# a comment line\n" +
		"\n" +
		"ssh-ed25519 " + sshTestKeyA + " alice@host-a.example\n" +
		`command="/usr/bin/backup --now",no-pty,from="203.0.113.10" ssh-ed25519 ` + sshTestKeyB + " deploy key\n" +
		"ssh-ed25519 not-base64-at-all broken\n"
	keys, diags := ParseAuthorizedKeys([]byte(in))
	if len(keys) != 2 {
		t.Fatalf("keys %+v", keys)
	}
	if len(diags) != 1 || diags[0].Code != privDiagRecordUnparsed {
		t.Fatalf("diagnostics %+v", diags)
	}
	if keys[0].Type != "ssh-ed25519" || keys[0].Fingerprint != sshTestKeyAFingerprint || keys[0].Slug != sshTestKeyASlug {
		t.Fatalf("first key %+v", keys[0])
	}
	if keys[0].Line != 3 || len(keys[0].Options) != 0 {
		t.Fatalf("first key %+v", keys[0])
	}
	second := keys[1]
	if second.Fingerprint != sshTestKeyBFingerprint {
		t.Fatalf("second fingerprint %q", second.Fingerprint)
	}
	if strings.Join(second.Options, ",") != "command,from,no-pty" {
		t.Fatalf("options %v, want the names only", second.Options)
	}
	// Nothing recorded may carry the key body, the comment or an option value.
	for _, k := range keys {
		rendered := k.Type + k.Fingerprint + k.Slug + strings.Join(k.Options, ",")
		for _, forbidden := range []string{sshTestKeyA[8:], sshTestKeyB[8:], "alice@host-a.example", "/usr/bin/backup", "203.0.113.10"} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("key record carries %q: %+v", forbidden, k)
			}
		}
	}
}

// TestParseAuthorizedKeysFingerprintMatchesTheDigest checks the pinned value
// against the definition: the unpadded base64 of the SHA-256 of the key blob.
func TestParseAuthorizedKeysFingerprintMatchesTheDigest(t *testing.T) {
	blob, err := base64.StdEncoding.DecodeString(sshTestKeyA)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	sum := sha256.Sum256(blob)
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if want != sshTestKeyAFingerprint {
		t.Fatalf("pinned fingerprint %q, computed %q", sshTestKeyAFingerprint, want)
	}
	if alg, ok := sshBlobAlgorithm(blob); !ok || alg != "ssh-ed25519" {
		t.Fatalf("algorithm %q ok=%v", alg, ok)
	}
	if _, ok := sshBlobAlgorithm([]byte("not a blob")); ok {
		t.Fatalf("a non blob was accepted as a key")
	}
}

func TestParseAuthorizedKeyOptions(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"no-pty", "no-pty"},
		{`command="a,b",no-agent-forwarding`, "command,no-agent-forwarding"},
		{`environment="X=1",restrict`, "environment,restrict"},
		{`command="say \"hi\", now",no-pty`, "command,no-pty"},
		{"NO-PTY,no-pty", "no-pty"},
	}
	for _, c := range cases {
		if got := strings.Join(ParseAuthorizedKeyOptions(c.in), ","); got != c.want {
			t.Fatalf("ParseAuthorizedKeyOptions(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSSHProbeUnprivileged is the shape of the trial host: the declared state
// is readable, the effective state is not (testdata
// ssh/sshd-T-unprivileged.stderr.txt, expected_probe_status
// permission_denied).
func TestSSHProbeUnprivileged(t *testing.T) {
	files := probe.FakeFiles{Files: map[string][]byte{
		SSHDConfigPath: privFixture(t, "ssh/sshd_config.txt"),
		"/home/alice/.ssh/authorized_keys": []byte(
			"ssh-ed25519 " + sshTestKeyA + " alice@host-a.example\n"),
	}}
	res, items := privRunProbe(t, NewSSHProbe(), sshFixtureRunner(t), files)
	if res.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	if !privWarned(res, sshDiagEffectiveNotObservable) {
		t.Fatalf("the missing effective state was not reported: %+v", res.Warnings)
	}
	if privHasArtifact(res, ArtifactSSHEffective) {
		t.Fatalf("an effective artifact was produced although sshd -T refused")
	}
	declared := privArtifact(t, res, ArtifactSSHDeclared)
	if declared.State != trustfreeze.StateDeclared {
		t.Fatalf("declared artifact state %q: declared must never be promoted", declared.State)
	}
	privWantAttr(t, declared, "passwordauthentication", "yes")
	privWantAttr(t, declared, "permitemptypasswords", "yes")
	privWantAttr(t, declared, sshAttrIncludeFiles, "0")
	privWantAttr(t, declared, sshAttrSourceFiles, SSHDConfigPath)

	dir := privArtifact(t, res, ArtifactSSHDirectory)
	privWantAttr(t, dir, sshAttrEntryCount, "23")
	privWantAttr(t, dir, sshAttrConfigLike, "10")

	file := privArtifact(t, res, ArtifactSSHConfigFilePrefix+"sshd_config")
	privWantAttr(t, file, privAttrSize, "3257")

	key := privArtifact(t, res, ArtifactSSHAuthorizedKeyPrefix+"alice/"+sshTestKeyASlug)
	privWantAttr(t, key, sshAttrFingerprint, sshTestKeyAFingerprint)
	privWantAttr(t, key, sshAttrKeyType, "ssh-ed25519")
	privWantAttr(t, key, privAttrAccount, "alice")
	if key.State != trustfreeze.StateDeclared {
		t.Fatalf("a key in authorized_keys is declared, not %q", key.State)
	}
	keyFile := privArtifact(t, res, ArtifactSSHAuthorizedKeysPrefix+"alice")
	privWantAttr(t, keyFile, sshAttrKeyCount, "1")
	privWantAttr(t, keyFile, privAttrPath, ".ssh/authorized_keys")

	// No absolute home path and no key body anywhere in the artifacts or the
	// evidence.
	for _, a := range res.NormalizedState {
		for k, v := range a.Attributes {
			if strings.Contains(v, "/home/alice") || strings.Contains(v, sshTestKeyA[8:]) {
				t.Fatalf("artifact %s attribute %s leaks %q", a.ID, k, v)
			}
		}
	}
	for _, it := range items {
		if strings.Contains(string(it.Data.Bytes()), sshTestKeyA[8:]) {
			t.Fatalf("evidence %s carries key material", it.Name)
		}
	}
	// The version banner of sshd comes from stderr; a probe that reads only
	// stdout records nothing.
	found := false
	for _, tool := range res.Tools {
		if tool.Name == sshdExe && strings.HasPrefix(tool.ToolVersion, "OpenSSH_9.6p1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("sshd version not recorded: %+v", res.Tools)
	}
}

// TestSSHProbeEffectiveObserved is the root run: sshd answers, and only then
// does an observed artifact exist.
func TestSSHProbeEffectiveObserved(t *testing.T) {
	r := sshFixtureRunner(t)
	r.Script(sshdExe, []string{"-T"}, probe.FakeResponse{Stdout: []byte(
		"port 22\npermitrootlogin prohibit-password\npasswordauthentication no\nusepam yes\n")})
	files := probe.FakeFiles{Files: map[string][]byte{SSHDConfigPath: privFixture(t, "ssh/sshd_config.txt")}}
	res, _ := privRunProbe(t, NewSSHProbe(), r, files)
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	eff := privArtifact(t, res, ArtifactSSHEffective)
	if eff.State != trustfreeze.StateObserved {
		t.Fatalf("effective artifact state %q", eff.State)
	}
	privWantAttr(t, eff, "passwordauthentication", "no")
	privWantAttr(t, eff, "port", "22")
	// Declared and observed disagree here, and both are recorded as what they
	// are (playbook L3).
	privWantAttr(t, privArtifact(t, res, ArtifactSSHDeclared), "passwordauthentication", "yes")
}

// TestSSHProbeDropInWins runs the probe with a drop-in file, the way a
// cloud-init host ships it.
func TestSSHProbeDropInWins(t *testing.T) {
	r := sshFixtureRunner(t)
	r.Script("ls", []string{"-la", SSHDConfigDir}, probe.FakeResponse{Stdout: []byte(
		"total 8\n" +
			"drwxr-xr-x 2 root root 4096 Sep 23 06:15 .\n" +
			"drwxr-xr-x 4 root root 4096 Sep 23 06:15 ..\n" +
			"-rw-r--r-- 1 root root   30 Sep 23 06:15 50-cloud-init.conf\n")})
	files := probe.FakeFiles{Files: map[string][]byte{
		SSHDConfigPath:                        privFixture(t, "ssh/sshd_config.txt"),
		SSHDConfigDir + "/50-cloud-init.conf": []byte("PasswordAuthentication no\n"),
	}}
	res, _ := privRunProbe(t, NewSSHProbe(), r, files)
	declared := privArtifact(t, res, ArtifactSSHDeclared)
	privWantAttr(t, declared, "passwordauthentication", "no")
	privWantAttr(t, declared, sshAttrIncludeFiles, "1")
	if !privHasArtifact(res, ArtifactSSHConfigFilePrefix+"sshd_config.d/50-cloud-init.conf") {
		t.Fatalf("the drop-in has no file artifact: %v", privArtifactIDs(res))
	}
}

// TestSSHProbeUnreadableKeyFileIsAGap: another account's key file that cannot
// be read is a gap, never an empty key list. The gap is an artifact of its
// own, the way linux.sudo records an unreadable rule file, so the capability
// resolver can say that this document is short of a source instead of
// reading the absence as "no key" (F4). The artifact claims no key: a file
// nobody read has no key count.
func TestSSHProbeUnreadableKeyFileIsAGap(t *testing.T) {
	r := sshFixtureRunner(t)
	r.Script(sshdExe, []string{"-T"}, probe.FakeResponse{Stdout: []byte("port 22\nusepam yes\n")})
	files := probe.FakeFiles{
		Files: map[string][]byte{SSHDConfigPath: privFixture(t, "ssh/sshd_config.txt")},
		// The account name follows the repository's standard cast; the gate
		// scripts/check-no-real-names.sh keeps a home path from carrying
		// anything else.
		Errs: map[string]error{"/home/alice/.ssh/authorized_keys": fs.ErrPermission},
	}
	res, _ := privRunProbe(t, NewSSHProbe(), r, files)
	if res.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	gap := privArtifact(t, res, ArtifactSSHAuthorizedKeysPrefix+"alice")
	privWantAttr(t, gap, privAttrReadable, "false")
	if _, ok := gap.Attributes[sshAttrKeyCount]; ok {
		t.Fatalf("a file nobody read has no key count: %+v", gap.Attributes)
	}
	for _, a := range res.NormalizedState {
		if strings.HasPrefix(a.ID, ArtifactSSHAuthorizedKeyPrefix+"alice/") {
			t.Fatalf("a key artifact was invented for a file that was never read: %s", a.ID)
		}
	}
	if !privWarned(res, probe.DiagFieldPermissionDenied) {
		t.Fatalf("the unreadable key file was not reported: %+v", res.Warnings)
	}
}

// TestSSHProbeUnsupportedPlatform keeps the probe honest elsewhere.
func TestSSHProbeUnsupportedPlatform(t *testing.T) {
	p := NewSSHProbe()
	if sup := p.Support(context.Background(), probe.HostContext{GOOS: "windows"}); sup.Available {
		t.Fatalf("support %+v", sup)
	}
	cc, _ := privContext(SSHProbeID, probe.NewFakeRunner(), probe.FakeFiles{})
	cc.GOOS = "windows"
	if res := p.Collect(context.Background(), cc); res.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("status %q", res.Status)
	}
}

// TestParsePasswdAccounts reads the recorded account database and keeps only
// what the key lookup needs.
func TestParsePasswdAccounts(t *testing.T) {
	accounts := parsePasswdAccounts(privFixture(t, "users/getent-passwd.txt"))
	if len(accounts) != 53 {
		t.Fatalf("accounts %d, want the 53 of the fixture", len(accounts))
	}
	byName := map[string]sshAccount{}
	for _, a := range accounts {
		byName[a.Name] = a
	}
	alice := byName["alice"]
	if alice.UID != 1000 || alice.Home != "/home/alice" || alice.Shell != "/bin/bash" {
		t.Fatalf("alice %+v", alice)
	}
	// The GECOS field carries a person's name and must not be reachable from
	// the parsed record.
	for _, a := range accounts {
		if strings.Contains(a.Name+a.Home+a.Shell, "Alice Example") {
			t.Fatalf("the GECOS field survived: %+v", a)
		}
	}
}

// TestSSHArtifactIDs pins the id shape (SPEC-0466 R4).
func TestSSHArtifactIDs(t *testing.T) {
	for _, id := range []string{
		ArtifactSSHDeclared, ArtifactSSHEffective, ArtifactSSHDirectory,
		ArtifactSSHConfigFilePrefix + "sshd_config",
		ArtifactSSHConfigFilePrefix + "sshd_config.d/50-cloud-init.conf",
		ArtifactSSHMatchPrefix + "1",
		ArtifactSSHAuthorizedKeysPrefix + "alice",
		ArtifactSSHAuthorizedKeyPrefix + "alice/" + sshTestKeyASlug,
	} {
		if err := trustfreeze.ValidateArtifactID(id); err != nil {
			t.Fatalf("artifact id %q: %v", id, err)
		}
	}
}

// TestSSHProbeDeclaredContract pins what the probe promises the capture
// engine.
func TestSSHProbeDeclaredContract(t *testing.T) {
	p := NewSSHProbe()
	d := p.Descriptor()
	if d.ID != SSHProbeID || d.RequiredPrivilege != probe.PrivilegeUser {
		t.Fatalf("descriptor %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if got := strings.Join(p.RequiredTools(), ","); got != "getent,ls,sshd" {
		t.Fatalf("required tools %q", got)
	}
	// The key lookup may only reach the two home roots and the configuration
	// directory; anything else is refused by the file reader.
	if got := strings.Join(SSHAllowedRoots(), ","); got != SSHDir+",/home,/root" {
		t.Fatalf("allowed roots %q", got)
	}
}

// TestSSHProbeMatchBlockArtifact: a conditional block is recorded as its own
// artifact, with the criteria and the keywords it sets.
func TestSSHProbeMatchBlockArtifact(t *testing.T) {
	r := sshFixtureRunner(t)
	r.Script(sshdExe, []string{"-T"}, probe.FakeResponse{Stdout: []byte("port 22\nusepam yes\n")})
	cfg := "PasswordAuthentication no\n" +
		"Match Group sudo\n" +
		"    PermitRootLogin yes\n" +
		"    X11Forwarding yes\n"
	files := probe.FakeFiles{Files: map[string][]byte{SSHDConfigPath: []byte(cfg)}}
	res, _ := privRunProbe(t, NewSSHProbe(), r, files)
	m := privArtifact(t, res, ArtifactSSHMatchPrefix+"1")
	privWantAttr(t, m, sshAttrCriteria, "Group sudo")
	privWantAttr(t, m, sshAttrKeywords, "permitrootlogin,x11forwarding")
	privWantAttr(t, m, privAttrLine, "2")
	declared := privArtifact(t, res, ArtifactSSHDeclared)
	privWantAttr(t, declared, sshAttrMatchBlocks, "1")
	if _, ok := declared.Attributes["permitrootlogin"]; ok {
		t.Fatalf("the conditional value became global state: %+v", declared.Attributes)
	}
}

// TestSSHProbeWithoutSSHD: the tool is missing, so the effective state is not
// observable. The declared state was read, so the probe is partial with the
// sshd gap named, not permission_denied, not a silent fallback to the declared
// values, and not unavailable: playbook L1 reserves unavailable for a missing
// source that leaves nothing behind, and this run produced three artifacts.
// (This assertion was changed for review finding F18; the earlier version of
// the test required unavailable and therefore held the defect in place.)
func TestSSHProbeWithoutSSHD(t *testing.T) {
	r := probe.NewFakeRunner()
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	r.Script(getentExe, []string{"--version"}, probe.FakeResponse{Stdout: privFixture(t, "users/getent-version.txt")})
	r.Script("ls", []string{"-la", SSHDir}, probe.FakeResponse{Stdout: privFixture(t, "ssh/ls-la-etc-ssh.txt")})
	r.Script("ls", []string{"-la", SSHDConfigDir}, probe.FakeResponse{Stdout: privFixture(t, "ssh/ls-la-sshd-config-d.txt")})
	r.Script(getentExe, []string{"passwd"}, probe.FakeResponse{Stdout: privFixture(t, "users/getent-passwd.txt")})
	files := probe.FakeFiles{Files: map[string][]byte{SSHDConfigPath: privFixture(t, "ssh/sshd_config.txt")}}
	res, _ := privRunProbe(t, NewSSHProbe(), r, files)
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	if res.Error != nil {
		t.Fatalf("a partial result that carries artifacts needs no error class: %+v", res.Error)
	}
	if !strings.Contains(res.Reason, "source is missing") {
		t.Fatalf("the reason does not name the gap: %q", res.Reason)
	}
	if !privWarned(res, sshDiagEffectiveNotObservable) {
		t.Fatalf("warnings %+v", res.Warnings)
	}
	if len(res.NormalizedState) == 0 {
		t.Fatal("the declared state was read and must be in the result")
	}
	// The declared state is still there, and still declared.
	if privArtifact(t, res, ArtifactSSHDeclared).State != trustfreeze.StateDeclared {
		t.Fatalf("the declared state changed because a tool was missing")
	}
}

// TestSSHProbeUnreadableDropIn: one unreadable include file outranks the
// readable main file in the status, and the readable part is still recorded.
func TestSSHProbeUnreadableDropIn(t *testing.T) {
	r := sshFixtureRunner(t)
	r.Script(sshdExe, []string{"-T"}, probe.FakeResponse{Stdout: []byte("port 22\nusepam yes\n")})
	r.Script("ls", []string{"-la", SSHDConfigDir}, probe.FakeResponse{Stdout: []byte(
		"total 8\n" +
			"drwx------ 2 root root 4096 Sep 23 06:15 .\n" +
			"drwxr-xr-x 4 root root 4096 Sep 23 06:15 ..\n" +
			"-rw------- 1 root root   30 Sep 23 06:15 99-secret.conf\n")})
	files := probe.FakeFiles{
		Files: map[string][]byte{SSHDConfigPath: privFixture(t, "ssh/sshd_config.txt")},
		Errs:  map[string]error{SSHDConfigDir + "/99-secret.conf": fs.ErrPermission},
	}
	res, _ := privRunProbe(t, NewSSHProbe(), r, files)
	if res.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	if privHasArtifact(res, ArtifactSSHConfigFilePrefix+"sshd_config.d/99-secret.conf") {
		t.Fatalf("an artifact was produced for a file that was never read")
	}
	privWantAttr(t, privArtifact(t, res, ArtifactSSHDeclared), sshAttrIncludeFiles, "0")
}

// TestSSHEvidenceClaims states what this build may claim for linux.
func TestSSHEvidenceClaims(t *testing.T) {
	claims := NewSSHProbe().EvidenceClaims()
	levels := claims[probe.PlatformLinux]
	if len(levels) != 2 || levels[0] != probe.FixtureTested || levels[1] != probe.CrossCompiled {
		t.Fatalf("claims %+v", claims)
	}
	if _, ok := claims[probe.PlatformWindows]; ok {
		t.Fatalf("a linux probe must claim nothing for windows: %+v", claims)
	}
}

// A missing sshd is a missing binary, and the two sentences the probe writes
// about it now name the directories that were searched. The status stays
// not_applicable only because a second, independent observation carries it:
// the declared configuration does not exist on disk either. Same sweep as
// the container runtime found at a snap path.
func TestSSHWithoutSSHDNamesTheSearchedDirectories(t *testing.T) {
	r := probe.NewFakeRunner().WithSearchDirs(netBastionSearchDirs...)
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	r.Script(getentExe, []string{"--version"}, probe.FakeResponse{Stdout: privFixture(t, "users/getent-version.txt")})
	r.Script(getentExe, []string{"passwd"}, probe.FakeResponse{Stdout: privFixture(t, "users/getent-passwd.txt")})
	r.Script("ls", []string{"-la", SSHDir}, probe.FakeResponse{Stderr: []byte("ls: cannot access '/etc/ssh': No such file or directory\n"), ExitCode: 2})
	r.Script("ls", []string{"-la", SSHDConfigDir}, probe.FakeResponse{Stderr: []byte("ls: cannot access '/etc/ssh/sshd_config.d': No such file or directory\n"), ExitCode: 2})

	res, _ := privRunProbe(t, NewSSHProbe(), r, probe.FakeFiles{})
	if res.Status != trustfreeze.StatusNotApplicable {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	for _, dir := range netBastionSearchDirs {
		if !strings.Contains(res.Reason, dir) {
			t.Errorf("reason %q does not name the searched directory %s", res.Reason, dir)
		}
	}
	if !strings.Contains(res.Reason, SSHDConfigPath) {
		t.Errorf("reason %q drops the second observation that carries it", res.Reason)
	}
	var msg string
	for _, w := range res.Warnings {
		if w.Code == sshDiagEffectiveNotObservable {
			msg = w.Message
		}
	}
	if strings.Contains(msg, "sshd is not installed") {
		t.Errorf("the diagnostic still turns a lookup miss into a claim about the host: %q", msg)
	}
	if !strings.Contains(msg, "/snap/bin") {
		t.Errorf("the diagnostic does not say where sshd was looked for: %q", msg)
	}
}
