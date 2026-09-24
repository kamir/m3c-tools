package linux

// Tests of linux.executables (SPEC-0471 TF06-R3).
//
// Two kinds of input, and the difference is deliberate.
//
// SHAPES come from fixtures under testdata/executables, transcribed from two
// real Ubuntu hosts and sanitized; testdata/executables/README.md names the
// exact argv, stream, exit code and tool version of every one of them. A parser
// is only proved by the bytes a tool really printed.
//
// LIMITS and REFUSALS come from scenarios this test builds: a file count above
// the cap, a size above the cap, a symlink that leaves the roots, a file the
// account may not read. No host of this laboratory has a 200 MB unit program or
// 300 services, and inventing a fixture that claims it does would be a false
// record. Where a scenario needs a "systemctl show" answer, it is built from
// the block shape of the measured fixture and says so.
//
// The file system is real in every test: the probe runs against a temporary
// directory through RootedProgramReader, which resolves, refuses and hashes
// with the production code. Nothing outside the test directory is touched, and
// no test needs a Linux host (playbook section 1 rules 5 and 10).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// execFixture reads one fixture of this probe.
func execFixture(t *testing.T, name string) []byte {
	t.Helper()
	return netFixture(t, "executables/"+name)
}

// ---------------------------------------------------------------------------
// The file seam: resolution, the two path rules, the hash.
// ---------------------------------------------------------------------------

// execTestFile is one entry of a test tree.
type execTestFile struct {
	// Size is the file length in bytes; the content is zeros. Content wins
	// when it is set.
	Size    int64
	Content string
	// Mode of the file; zero means 0755.
	Mode fs.FileMode
	// Unreadable sets the mode to 0000 after the file was written, which is
	// the one mode a zero value cannot express.
	Unreadable bool
	// Link makes the entry a symlink to this LOGICAL path, mapped into the
	// test tree. RawLink is a target taken verbatim, for a link that leaves
	// the tree.
	Link    string
	RawLink string
}

// execTestTree builds the tree and returns a reader rooted at it plus the
// directory. A tree with a symlink skips the test where the operating system
// does not let an unprivileged process create one (Windows without developer
// mode), because the case under test cannot exist there.
func execTestTree(t *testing.T, files map[string]execTestFile) (*RootedProgramReader, string) {
	t.Helper()
	dir := t.TempDir()
	disk := func(logical string) string {
		return filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(logical, "/")))
	}
	for _, logical := range sortedLogicalPaths(files) {
		f := files[logical]
		p := disk(logical)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", logical, err)
		}
		switch {
		case f.Link != "" || f.RawLink != "":
			target := f.RawLink
			if f.Link != "" {
				target = disk(f.Link)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Skipf("this operating system does not let the test create a symlink: %v", err)
			}
			continue
		case f.Content != "":
			mode := f.Mode
			if mode == 0 {
				mode = 0o755
			}
			if err := os.WriteFile(p, []byte(f.Content), mode); err != nil {
				t.Fatalf("write %s: %v", logical, err)
			}
			if f.Unreadable {
				if err := os.Chmod(p, 0o000); err != nil {
					t.Fatalf("chmod %s: %v", logical, err)
				}
			}
		default:
			fh, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				t.Fatalf("create %s: %v", logical, err)
			}
			// A sparse file: the measured size of a real program without the
			// bytes of one, so the chunked hash loop runs over a multi chunk
			// file without the test writing 30 MB.
			if err := fh.Truncate(f.Size); err != nil {
				t.Fatalf("truncate %s: %v", logical, errors.Join(err, fh.Close()))
			}
			if err := fh.Close(); err != nil {
				t.Fatalf("close %s: %v", logical, err)
			}
			if f.Mode != 0 {
				if err := os.Chmod(p, f.Mode); err != nil {
					t.Fatalf("chmod %s: %v", logical, err)
				}
			}
		}
	}
	return NewRootedProgramReader(ExecutableRoots(), ExecutableHomePrefixes(), dir), dir
}

func sortedLogicalPaths(files map[string]execTestFile) []string {
	out := make([]string, 0, len(files))
	for k := range files {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// execFileDigest hashes a file of the test tree through a second, independent
// path, so the digest the probe reports is compared against one this test
// computed itself.
func execFileDigest(t *testing.T, dir, logical string) (string, int64) {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(logical, "/"))))
	if err != nil {
		t.Fatalf("open %s: %v", logical, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		t.Fatalf("hash %s: %v", logical, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n
}

// TF06-R3: the reader resolves inside its roots and refuses everything else,
// and every refusal has its own reason.
func TestRootedProgramReaderResolve(t *testing.T) {
	reader, _ := execTestTree(t, map[string]execTestFile{
		"/usr/bin/prog":              {Content: "program bytes"},
		"/usr/local/bin/wrapper":     {Link: "/usr/bin/prog"},
		"/usr/local/bin/to-home":     {Link: "/home/alice/bin/agent"},
		"/home/alice/bin/agent":      {Content: "agent bytes"},
		"/usr/local/bin/out-of-tree": {RawLink: string(filepath.Separator) + "etc" + string(filepath.Separator) + "hosts"},
		"/usr/lib/plugins/keep":      {Content: "x"},
		"/etc/passwd":                {Content: "root:x:0:0"},
	})
	for _, tc := range []struct {
		name    string
		path    string
		want    string
		wantErr error
	}{
		{"a program under a root", "/usr/bin/prog", "/usr/bin/prog", nil},
		{"a symlink inside the roots", "/usr/local/bin/wrapper", "/usr/bin/prog", nil},
		{"a path with a dot segment", "/usr/bin/./prog", "/usr/bin/prog", nil},
		{"a symlink into a home directory", "/usr/local/bin/to-home", "", ErrExecutableHomePath},
		{"a symlink out of the tree", "/usr/local/bin/out-of-tree", "", ErrExecutableSymlinkEscape},
		{"a path outside the roots", "/etc/passwd", "", ErrExecutableOutsideRoots},
		{"a path under a home directory", "/home/alice/bin/agent", "", ErrExecutableHomePath},
		{"a relative path", "usr/bin/prog", "", ErrExecutableOutsideRoots},
		{"a directory", "/usr/lib/plugins", "", ErrExecutableNotRegular},
		{"a missing file", "/usr/bin/absent", "", fs.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := reader.Resolve(tc.path)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("Resolve(%q) failed: %v", tc.path, err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Resolve(%q) error %v, want %v", tc.path, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TF06-R3 with T-03b B3: the hash streams, it is the digest of the whole file,
// and the size limit refuses before anything is read.
func TestRootedProgramReaderHash(t *testing.T) {
	const bigSize = 22693016 // the measured size of /usr/bin/snap
	reader, dir := execTestTree(t, map[string]execTestFile{
		"/usr/bin/prog":  {Content: "program bytes"},
		"/usr/bin/big":   {Size: bigSize},
		"/usr/lib/plain": {Content: "not executable"},
		"/etc/passwd":    {Content: "root:x:0:0"},
	})
	ctx := context.Background()

	wantSum, wantSize := execFileDigest(t, dir, "/usr/bin/prog")
	sum, n, err := reader.Hash(ctx, "/usr/bin/prog", ExecutableMaxFileBytes)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if sum != wantSum || n != wantSize {
		t.Fatalf("Hash = %s/%d, want %s/%d", sum, n, wantSum, wantSize)
	}

	// A file larger than one chunk of the copy loop, so the loop itself is
	// covered and not only its first pass.
	if bigSize <= executablesHashChunkBytes {
		t.Fatalf("the big file of %d bytes does not exceed the chunk of %d", bigSize, executablesHashChunkBytes)
	}
	wantSum, wantSize = execFileDigest(t, dir, "/usr/bin/big")
	sum, n, err = reader.Hash(ctx, "/usr/bin/big", ExecutableMaxFileBytes)
	if err != nil {
		t.Fatalf("Hash of the big file: %v", err)
	}
	if sum != wantSum || n != wantSize {
		t.Fatalf("Hash of the big file = %s/%d, want %s/%d", sum, n, wantSum, wantSize)
	}

	// The cap refuses the file, and the error says which limit did it.
	if _, _, err := reader.Hash(ctx, "/usr/bin/prog", 4); !errors.Is(err, ErrExecutableTooLarge) {
		t.Fatalf("a file over the limit returned %v, want ErrExecutableTooLarge", err)
	}
	// The path rules apply to the hash as well, not only to the resolution.
	if _, _, err := reader.Hash(ctx, "/etc/passwd", ExecutableMaxFileBytes); !errors.Is(err, ErrExecutableOutsideRoots) {
		t.Fatalf("hashing outside the roots returned %v", err)
	}
	// A cancelled context stops the read.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := reader.Hash(cancelled, "/usr/bin/big", ExecutableMaxFileBytes); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled hash returned %v", err)
	}
}

// An unreadable file is permission_denied for that file and nothing else.
func TestRootedProgramReaderHashPermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a mode of 0000 does not deny a read on windows, so the case cannot be built here")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: a mode of 0000 denies nothing, so the case cannot be built here")
	}
	reader, _ := execTestTree(t, map[string]execTestFile{
		"/usr/bin/secret": {Content: "closed", Unreadable: true},
	})
	_, _, err := reader.Hash(context.Background(), "/usr/bin/secret", ExecutableMaxFileBytes)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("hashing an unreadable file returned %v, want a permission error", err)
	}
}

// The program behind a process comes from /proc/<pid>/exe, and the same rules
// decide about it.
func TestRootedProgramReaderProcessExecutable(t *testing.T) {
	reader, _ := execTestTree(t, map[string]execTestFile{
		"/usr/bin/prog":       {Content: "program bytes"},
		"/proc/2698/exe":      {Link: "/usr/bin/prog"},
		"/proc/2699/exe":      {RawLink: "/usr/bin/gone (deleted)"},
		"/proc/2700/exe":      {Link: "/home/alice/bin/agent"},
		"/home/alice/bin/age": {Content: "x"},
	})
	got, err := reader.ProcessExecutable("2698")
	if err != nil {
		t.Fatalf("ProcessExecutable: %v", err)
	}
	if got != "/usr/bin/prog" {
		t.Fatalf("ProcessExecutable = %q", got)
	}
	if _, err := reader.ProcessExecutable("2699"); !errors.Is(err, ErrExecutableDeletedTarget) {
		t.Fatalf("a deleted target returned %v", err)
	}
	if _, err := reader.ProcessExecutable("2700"); !errors.Is(err, ErrExecutableHomePath) {
		t.Fatalf("a link into a home directory returned %v", err)
	}
	if _, err := reader.ProcessExecutable("self"); !errors.Is(err, ErrExecutableBadPID) {
		t.Fatalf("a non numeric pid returned %v", err)
	}
	if _, err := reader.ProcessExecutable("4711"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an unknown pid returned %v", err)
	}
}

// ---------------------------------------------------------------------------
// The parsers, against the measured bytes.
// ---------------------------------------------------------------------------

// TF06-R3: the three measured "dpkg -S" line shapes, and the two traps.
func TestParseDpkgSearchFixtures(t *testing.T) {
	t.Run("the ordinary answer of both releases", func(t *testing.T) {
		for _, name := range []string{"dpkg-search.txt", "dpkg-search-2204.txt", "dpkg-search-unit-programs.txt"} {
			found, div, issues := ParseDpkgSearch(execFixture(t, name))
			if len(issues) != 0 {
				t.Fatalf("%s: %d issue(s): %v", name, len(issues), issues)
			}
			if len(div) != 0 {
				t.Fatalf("%s: a diversion was read where there is none", name)
			}
			for p, pkgs := range found {
				if !strings.HasPrefix(p, "/") {
					t.Fatalf("%s: %q is not a path", name, p)
				}
				if len(pkgs) != 1 {
					t.Fatalf("%s: %s has %d owners, want 1", name, p, len(pkgs))
				}
			}
		}
		found, _, _ := ParseDpkgSearch(execFixture(t, "dpkg-search.txt"))
		if got := found["/usr/sbin/sshd"]; len(got) != 1 || got[0] != "openssh-server" {
			t.Fatalf("/usr/sbin/sshd is owned by %v", got)
		}
		// The bastion case this probe exists for: a program under /usr/local
		// that a package owns, beside one that no package owns. The second one
		// is absent from stdout, which is the answer.
		found2204, _, _ := ParseDpkgSearch(execFixture(t, "dpkg-search-2204.txt"))
		if got := found2204["/usr/local/bin/mcli"]; len(got) != 1 || got[0] != "mcli" {
			t.Fatalf("/usr/local/bin/mcli is owned by %v", got)
		}
		if _, ok := found2204["/usr/local/bin/ngrok"]; ok {
			t.Fatal("a path the database does not know produced a stdout answer")
		}
		if _, ok := found2204["/snap/core22/1122/usr/bin/env"]; ok {
			t.Fatal("a file of a mounted snap produced a stdout answer")
		}
	})

	t.Run("many owners in one line", func(t *testing.T) {
		found, _, issues := ParseDpkgSearch(execFixture(t, "dpkg-search-multi-owner.txt"))
		if len(issues) != 0 {
			t.Fatalf("%d issue(s): %v", len(issues), issues)
		}
		pkgs := found["/etc/init.d"]
		if len(pkgs) != 31 {
			t.Fatalf("read %d owners, want the 31 of the measured line", len(pkgs))
		}
		if pkgs[0] != "spice-vdagent" || pkgs[len(pkgs)-1] != "console-setup-linux" {
			t.Fatalf("the owner list is %q ... %q", pkgs[0], pkgs[len(pkgs)-1])
		}
		for _, p := range pkgs {
			if strings.ContainsAny(p, " ,") {
				t.Fatalf("package name %q carries a space or a comma", p)
			}
		}
	})

	t.Run("a diversion is not an owner", func(t *testing.T) {
		found, div, issues := ParseDpkgSearch(execFixture(t, "dpkg-search-diversion.txt"))
		if len(issues) != 0 {
			t.Fatalf("%d issue(s): %v", len(issues), issues)
		}
		const p = "/usr/share/dict/words"
		if got := found[p]; len(got) != 1 || got[0] != "wamerican" {
			t.Fatalf("%s is owned by %v, want the one real owner", p, got)
		}
		if div[p] != "dictionaries-common" {
			t.Fatalf("the diverting package is %q", div[p])
		}
		for path, pkgs := range found {
			for _, pkg := range pkgs {
				if strings.Contains(pkg, "diversion") {
					t.Fatalf("%s: a diversion record was read as the package %q", path, pkg)
				}
			}
		}
		// The "to" line names a second path, which is a different file and
		// gets no owner from this answer.
		if _, ok := found[p+".pre-dictionaries-common"]; ok {
			t.Fatal("the target of the diversion was read as an owned path")
		}
	})

	t.Run("a line the parser cannot read", func(t *testing.T) {
		_, _, issues := ParseDpkgSearch([]byte("no colon here\n: /usr/bin/x\nopenssh-server: /usr/sbin/sshd\n"))
		if len(issues) != 2 {
			t.Fatalf("%d issue(s), want 2: %v", len(issues), issues)
		}
		for _, d := range issues {
			if d.Code != netDiagRecordUnparsed {
				t.Fatalf("diagnostic code %q", d.Code)
			}
			if strings.Contains(d.Message, "no colon here") {
				t.Fatalf("the diagnostic repeats the line content: %q", d.Message)
			}
		}
	})
}

// The snap rule reads the name out of the path, and only out of a path that
// really is inside a mounted snap.
func TestSnapNameFromPath(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/snap/core22/1122/usr/bin/env", "core22"},
		{"/snap/ollama/current/bin/ollama", "ollama"},
		{"/snap/bin/docker", ""},
		{"/snap/core22", ""},
		{"/snap", ""},
		{"/usr/bin/snap", ""},
		{"/usr/local/bin/ngrok", ""},
	} {
		if got := SnapNameFromPath(tc.path); got != tc.want {
			t.Errorf("SnapNameFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// The artifact id of a program carries no absolute path and survives
// trustfreeze.ValidateArtifactID (SPEC-0466 section 4.3: an artifact id is
// stable and holds no absolute or user specific path).
func TestExecutableArtifactID(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/usr/sbin/sshd", "executable/usr/sbin/sshd"},
		{"/snap/core22/1122/usr/bin/env", "executable/snap/core22/1122/usr/bin/env"},
		{"/opt/vendor/bin/with space", "executable/opt/vendor/bin/with_space"},
	} {
		got := ExecutableArtifactID(tc.path)
		if got != tc.want {
			t.Errorf("ExecutableArtifactID(%q) = %q, want %q", tc.path, got, tc.want)
		}
		if err := trustfreeze.ValidateArtifactID(got); err != nil {
			t.Errorf("%s: %v", got, err)
		}
	}
}

// The measured stat answers parse to the measured numbers, so a size cap has
// real sizes to refuse.
func TestParseStatOfExecutableFixtures(t *testing.T) {
	info, diags := ParseStat(execFixture(t, "stat-executables-2204.txt"))
	if len(diags) != 0 {
		t.Fatalf("%d diagnostic(s): %v", len(diags), diags)
	}
	for _, tc := range []struct{ path, mode, size string }{
		{"/usr/local/bin/ngrok", "0755", "32911522"},
		{"/usr/local/bin/mcli", "0755", "31068320"},
		{"/snap/core22/1122/usr/bin/env", "0755", "43968"},
		{"/usr/lib/snapd/snapd", "0755", "29950624"},
	} {
		si := info[tc.path]
		if !si.Known || si.Mode != tc.mode || si.Size != tc.size || si.Owner != "root" || si.Group != "root" {
			t.Errorf("%s = %+v", tc.path, si)
		}
	}
}

// ---------------------------------------------------------------------------
// The probe: descriptor, support, collect.
// ---------------------------------------------------------------------------

// execRunner scripts the four tools with the version answers of the trial host.
func execRunner(t *testing.T) *probe.FakeRunner {
	t.Helper()
	return probe.NewFakeRunner().
		AddTool(systemctlExe, "/usr/bin/systemctl").
		AddTool(ListenersTool, "/usr/sbin/ss").
		AddTool(ExecutablesToolStat, "/usr/bin/stat").
		AddTool(ExecutablesToolDpkg, "/usr/bin/dpkg").
		Script(ExecutablesToolStat, []string{"--version"},
			probe.FakeResponse{Stdout: execFixture(t, "stat-version.txt")}).
		Script(ExecutablesToolDpkg, []string{"--version"},
			probe.FakeResponse{Stdout: execFixture(t, "dpkg-version.txt")})
}

func execShowArgs(units ...string) []string {
	return append([]string{"show", "--no-pager", "-p", "Id,ExecStart"}, units...)
}

func execStatArgs(paths ...string) []string {
	return append([]string{"-L", "-c", "%n %a %U %G %s"}, paths...)
}

func execDpkgArgs(paths ...string) []string {
	return append([]string{"-S"}, paths...)
}

// execShowAnswer builds a "systemctl show" answer in the block shape of
// testdata/executables/systemctl-show-execstart.txt: the manager answers in its
// own property order and separates units with a blank line. It is used where a
// scenario needs paths no host of this laboratory has.
func execShowAnswer(unitToPath map[string]string) []byte {
	var b strings.Builder
	for _, unit := range netSortedKeys(unitToPath) {
		if p := unitToPath[unit]; p != "" {
			fmt.Fprintf(&b, "ExecStart={ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n", p, p)
		}
		fmt.Fprintf(&b, "Id=%s\n\n", unit)
	}
	return []byte(b.String())
}

// execUnitFileList builds a unit file list in the column shape of the measured
// subset fixture: name, state, preset, separated by runs of spaces.
func execUnitFileList(units map[string]string) []byte {
	var b strings.Builder
	for _, unit := range netSortedKeys(units) {
		fmt.Fprintf(&b, "%-60s %-15s enabled\n", unit, units[unit])
	}
	return []byte(b.String())
}

func execArtifact(t *testing.T, res trustfreeze.ProbeResult, id string) trustfreeze.Artifact {
	t.Helper()
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return a
		}
	}
	var ids []string
	for _, a := range res.NormalizedState {
		ids = append(ids, a.ID)
	}
	t.Fatalf("artifact %s is missing; the result holds %v", id, ids)
	return trustfreeze.Artifact{}
}

func execHasArtifact(res trustfreeze.ProbeResult, id string) bool {
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return true
		}
	}
	return false
}

func execWarning(res trustfreeze.ProbeResult, code, contains string) bool {
	for _, w := range res.Warnings {
		if w.Code == code && strings.Contains(w.Message, contains) {
			return true
		}
	}
	return false
}

// The descriptor is valid, names linux only and names its executables.
func TestExecutablesDescriptor(t *testing.T) {
	p := NewExecutablesProbe()
	d := p.Descriptor()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(d.Platforms) != 1 || d.Platforms[0] != probe.PlatformLinux {
		t.Fatalf("platforms %v", d.Platforms)
	}
	if d.RequiredPrivilege != probe.PrivilegeUser {
		t.Fatalf("privilege %q: this probe never elevates (playbook L2)", d.RequiredPrivilege)
	}
	// This build has fixture tested parsers and it cross compiles; whether the
	// probe ran on a real Linux host is not decided in code (TF06-R7).
	claims := p.EvidenceClaims()[probe.PlatformLinux]
	if !slices.Contains(claims, probe.FixtureTested) || !slices.Contains(claims, probe.CrossCompiled) {
		t.Fatalf("evidence claims %v", claims)
	}
	for _, c := range claims {
		// The type has exactly two levels, and neither of them is the one a
		// build cannot prove about itself.
		if c != probe.FixtureTested && c != probe.CrossCompiled {
			t.Fatalf("the probe claims the evidence level %q, which no build can prove about itself", c)
		}
	}
	want := []string{ExecutablesToolDpkg, ListenersTool, ExecutablesToolStat, systemctlExe}
	if got := p.RequiredTools(); !sort.StringsAreSorted(got) || len(got) != len(want) {
		t.Fatalf("RequiredTools = %v, want the four sorted names %v", got, want)
	}
}

// Support: linux only, and the two sources decide.
func TestExecutablesSupport(t *testing.T) {
	for _, tc := range []struct {
		name      string
		goos      string
		runner    *probe.FakeRunner
		available bool
		status    trustfreeze.ProbeStatus
	}{
		{"both sources", "linux", probe.NewFakeRunner().AddTool(systemctlExe, "/usr/bin/systemctl").AddTool(ListenersTool, "/usr/sbin/ss"), true, ""},
		{"only systemctl", "linux", probe.NewFakeRunner().AddTool(systemctlExe, "/usr/bin/systemctl"), true, ""},
		{"only ss", "linux", probe.NewFakeRunner().AddTool(ListenersTool, "/usr/sbin/ss"), true, ""},
		{"no source", "linux", probe.NewFakeRunner(), false, trustfreeze.StatusUnavailable},
		{"sources not executable", "linux", probe.NewFakeRunner().DenyTool(systemctlExe, "/usr/bin/systemctl").DenyTool(ListenersTool, "/usr/sbin/ss"), false, trustfreeze.StatusPermissionDenied},
		{"another platform", "darwin", probe.NewFakeRunner().AddTool(systemctlExe, "/usr/bin/systemctl"), false, trustfreeze.StatusUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := netTestHost(tc.runner)
			host.GOOS = tc.goos
			s := NewExecutablesProbe().Support(context.Background(), host)
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
			if s.Available != tc.available {
				t.Fatalf("available = %v, want %v (%s)", s.Available, tc.available, s.Reason)
			}
			if !tc.available && s.Status != tc.status {
				t.Fatalf("status %q, want %q", s.Status, tc.status)
			}
		})
	}
}

// The bastion case, end to end from the measured shapes of that host: a unit
// starts a program under /usr/local/bin, the same program holds a listening
// socket, and no package owns it (T-03b B4).
func TestExecutablesCollectUnownedProgram(t *testing.T) {
	const ngrok = "/usr/local/bin/ngrok"
	reader, dir := execTestTree(t, map[string]execTestFile{
		ngrok:            {Size: 32911522}, // the size the bastion measured
		"/proc/2698/exe": {Link: ngrok},
	})
	runner := execRunner(t).
		Script(ExecutablesToolStat, []string{"--version"}, probe.FakeResponse{Stdout: execFixture(t, "stat-version-2204.txt")}).
		Script(ExecutablesToolDpkg, []string{"--version"}, probe.FakeResponse{Stdout: execFixture(t, "dpkg-version-2204.txt")}).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execFixture(t, "systemctl-list-unit-files-subset-2204.txt")}).
		Script(systemctlExe, execShowArgs("ngrok-host-a.service", "ssh.socket"),
			probe.FakeResponse{Stdout: execFixture(t, "systemctl-show-execstart-2204.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"},
			probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-H-lntup.txt")}).
		Script(ExecutablesToolStat, execStatArgs(ngrok),
			probe.FakeResponse{Stdout: []byte("/usr/local/bin/ngrok 755 root root 32911522\n")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(ngrok), probe.FakeResponse{
			ExitCode: 1,
			Stderr:   execFixture(t, "dpkg-search-2204.stderr.txt"),
		})
	cc, ev := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	// The listener fixture names an owning process for one of its 51 sockets,
	// which is the unprivileged reality: the run is partial and says why.
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q with reason %q, want partial: the owner of 50 sockets is not observable", res.Status, res.Reason)
	}
	if !strings.Contains(res.Reason, "listening socket") {
		t.Fatalf("reason %q does not name the listener gap", res.Reason)
	}

	a := execArtifact(t, res, "executable/usr/local/bin/ngrok")
	wantSum, wantSize := execFileDigest(t, dir, ngrok)
	for k, want := range map[string]string{
		execAttrPath:          ngrok,
		execAttrHashState:     HashStateCaptured,
		execAttrSHA256:        wantSum,
		execAttrSize:          strconv.FormatInt(wantSize, 10),
		execAttrMode:          "0755",
		execAttrOwner:         "root",
		execAttrGroup:         "root",
		execAttrPackageOwner:  PackageOwnerNone,
		execAttrPackageSource: PackageSourceDpkgNoMatch,
		execAttrOrigins:       OriginListenerProcess + "," + OriginSystemdExecStart,
		execAttrUnits:         "ngrok-host-a.service",
	} {
		if got := a.Attributes[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if a.State != trustfreeze.StateObserved {
		t.Errorf("state %q, want observed: the bytes were read", a.State)
	}
	if a.Digest == "" {
		t.Error("the artifact has no digest")
	}
	// The finding is stated as a diagnostic too, so a reader of the probe
	// result sees it without walking every artifact.
	if !execWarning(res, DiagExecutableUnowned, ngrok) {
		t.Errorf("no %s diagnostic names %s", DiagExecutableUnowned, ngrok)
	}

	set := execArtifact(t, res, ArtifactExecutables)
	for k, want := range map[string]string{
		execAttrProgramCount:     "1",
		execAttrHashedCount:      "1",
		execAttrOwnerNoneCount:   "1",
		execAttrOwnerUnknownCnt:  "0",
		execAttrFromSystemdCount: "1",
		execAttrFromSocketCount:  "1",
		execAttrRefusedCount:     "0",
		execAttrUnreadableCount:  "0",
		execAttrTooLargeCount:    "0",
		execAttrMaxFileBytes:     strconv.FormatInt(ExecutableMaxFileBytes, 10),
		execAttrMaxFiles:         strconv.Itoa(ExecutableMaxFiles),
		execAttrHashAlgorithm:    "sha256",
		execAttrStatVersion:      "stat (GNU coreutils) 8.32",
		execAttrDpkgVersion:      "Debian 'dpkg' package management program version 1.21.1 (amd64).",
	} {
		if got := set.Attributes[k]; got != want {
			t.Errorf("set artifact %s = %q, want %q", k, got, want)
		}
	}
	if got := set.Attributes[execAttrRoots]; got != strings.Join(ExecutableRoots(), ",") {
		t.Errorf("the set artifact does not state the roots: %q", got)
	}

	// The evidence is the output of the two tools only this probe reads.
	var names []string
	for _, it := range ev.Close() {
		names = append(names, it.Name)
	}
	sort.Strings(names)
	for _, want := range []string{"dpkg-search-01.stderr.txt", "dpkg-version.txt", "stat-01.txt", "stat-version.txt"} {
		if !slices.Contains(names, want) {
			t.Errorf("evidence %s is missing from %v", want, names)
		}
	}
}

// The trial host case: three unit programs, every one of them owned by a
// package, and the ownership comes from the measured answer.
func TestExecutablesCollectOwnedPrograms(t *testing.T) {
	paths := []string{"/usr/bin/snap", "/usr/sbin/cron", "/usr/sbin/sshd"}
	tree := map[string]execTestFile{
		"/usr/bin/snap":  {Size: 22693016},
		"/usr/sbin/cron": {Size: 60080},
		"/usr/sbin/sshd": {Size: 921416},
	}
	reader, _ := execTestTree(t, tree)
	units := []string{"cron.service", "man-db.timer", "snap.cups.cupsd.service", "ssh.service"}
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execFixture(t, "systemctl-list-unit-files-subset.txt")}).
		Script(systemctlExe, execShowArgs(units...),
			probe.FakeResponse{Stdout: execFixture(t, "systemctl-show-execstart.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")}).
		Script(ExecutablesToolStat, execStatArgs(paths...),
			probe.FakeResponse{Stdout: execFixture(t, "stat-unit-programs.txt")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(paths...),
			probe.FakeResponse{Stdout: execFixture(t, "dpkg-search-unit-programs.txt")})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, reason %q, warnings %+v", res.Status, res.Reason, res.Warnings)
	}
	for path, wantPkg := range map[string]string{
		"/usr/sbin/sshd": "openssh-server",
		"/usr/sbin/cron": "cron",
		"/usr/bin/snap":  "snapd",
	} {
		a := execArtifact(t, res, ExecutableArtifactID(path))
		if got := a.Attributes[execAttrPackageOwner]; got != wantPkg {
			t.Errorf("%s: package_owner = %q, want %q", path, got, wantPkg)
		}
		if got := a.Attributes[execAttrPackageSource]; got != PackageSourceDpkg {
			t.Errorf("%s: package_owner_source = %q", path, got)
		}
		if a.Attributes[execAttrSHA256] == "" || a.Attributes[execAttrHashState] != HashStateCaptured {
			t.Errorf("%s has no digest: %v", path, a.Attributes)
		}
	}
	// The timer names no program, so it produces no artifact and no gap: a
	// unit without an ExecStart is not a unit whose program is unknown.
	set := execArtifact(t, res, ArtifactExecutables)
	if got := set.Attributes[execAttrProgramCount]; got != "3" {
		t.Fatalf("program_count = %q, want 3", got)
	}
	if got := set.Attributes[execAttrFromSocketCount]; got != "0" {
		t.Fatalf("from_listener_count = %q, want 0: the socket list of this scenario is empty", got)
	}

	// The provenance names its sources by tool and subcommand. A batched call
	// names up to 64 paths, and repeating those in every artifact would make
	// the provenance longer than the facts it carries.
	a := execArtifact(t, res, ExecutableArtifactID("/usr/sbin/sshd"))
	wantSources := []string{
		"command:dpkg --version", "command:dpkg -S", "command:ss -H -lntup",
		"command:stat", "command:stat --version",
		"command:systemctl list-unit-files --no-legend --no-pager",
		"command:systemctl show",
	}
	if got := a.Provenance.Sources; !slices.Equal(got, wantSources) {
		t.Errorf("sources = %q, want %q", got, wantSources)
	}
	for _, src := range a.Provenance.Sources {
		if len(src) > 60 {
			t.Errorf("the source %q repeats an argument vector", src)
		}
	}
	if a.Provenance.ToolVersion != "stat (GNU coreutils) 9.4" {
		t.Errorf("tool_version = %q", a.Provenance.ToolVersion)
	}

	// Two runs of the same host produce the same bytes (playbook L8).
	cc2, _ := netTestCollect(ExecutablesProbeID, runner)
	res2 := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc2)
	first, err := trustfreeze.MarshalCanonical(res.NormalizedState)
	if err != nil {
		t.Fatal(err)
	}
	second, err := trustfreeze.MarshalCanonical(res2.NormalizedState)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("two runs produced different artifacts")
	}
}

// A program inside a mounted snap is owned by that snap, and dpkg is not asked
// about it: the database does not hold it (measured on the bastion).
func TestExecutablesCollectSnapProgram(t *testing.T) {
	const env = "/snap/core22/1122/usr/bin/env"
	reader, _ := execTestTree(t, map[string]execTestFile{
		env:              {Size: 43968},
		"/proc/2698/exe": {Link: env},
	})
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: []byte("")}).
		Script(ListenersTool, []string{"-H", "-lntup"},
			probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-H-lntup.txt")}).
		Script(ExecutablesToolStat, execStatArgs(env),
			probe.FakeResponse{Stdout: []byte("/snap/core22/1122/usr/bin/env 755 root root 43968\n")})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	a := execArtifact(t, res, ExecutableArtifactID(env))
	if got := a.Attributes[execAttrPackageOwner]; got != "core22" {
		t.Errorf("package_owner = %q, want the snap name", got)
	}
	if got := a.Attributes[execAttrPackageSource]; got != PackageSourceSnapPath {
		t.Errorf("package_owner_source = %q", got)
	}
	if got := a.Attributes[execAttrOrigins]; got != OriginListenerProcess {
		t.Errorf("discovered_by = %q", got)
	}
	// dpkg was never called: not for the snap path, not at all.
	for _, call := range runner.Calls() {
		if call.Executable == ExecutablesToolDpkg && len(call.Args) > 0 && call.Args[0] == "-S" {
			t.Fatalf("dpkg -S was called for %v although every program is a snap file", call.Args)
		}
	}
}

// The limits and the refusals (T-03b B3). The paths of this scenario exist on
// no host of this laboratory, so the answers are built here and say so.
func TestExecutablesCollectLimitsAndRefusals(t *testing.T) {
	const (
		big     = "/opt/vendor/bin/oversized"
		outside = "/etc/init.d/vendor-agent"
		good    = "/usr/local/bin/agent"
	)
	tree := map[string]execTestFile{
		good:                          {Content: "agent bytes"},
		big:                           {Content: "the stat answer claims this is over the cap"},
		outside:                       {Content: "x"},
		"/usr/bin/absent-placeholder": {Content: "x"},
	}
	reader, _ := execTestTree(t, tree)
	unitPaths := map[string]string{
		"a-good.service":    good,
		"b-big.service":     big,
		"c-outside.service": outside,
		"d-missing.service": "/usr/bin/absent",
	}
	units := netSortedKeys(unitPaths)
	statPaths := []string{big, good}
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execUnitFileList(map[string]string{
				"a-good.service": "enabled", "b-big.service": "enabled",
				"c-outside.service": "enabled", "d-missing.service": "enabled",
			})}).
		Script(systemctlExe, execShowArgs(units...), probe.FakeResponse{Stdout: execShowAnswer(unitPaths)}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")}).
		// The measured stat line shape with a size above the cap, because no
		// program of either host is that large.
		Script(ExecutablesToolStat, execStatArgs(statPaths...), probe.FakeResponse{Stdout: []byte(
			big + " 755 root root 209715200\n" + good + " 755 root root 11\n")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(statPaths...), probe.FakeResponse{
			ExitCode: 1,
			Stderr:   []byte("dpkg-query: no path found matching pattern " + big + "\ndpkg-query: no path found matching pattern " + good + "\n"),
		})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial: two paths were refused and one file is over the cap", res.Status)
	}
	// Over the size cap: the artifact exists, the digest does not, and the
	// state says which limit stopped it.
	a := execArtifact(t, res, ExecutableArtifactID(big))
	if got := a.Attributes[execAttrHashState]; got != HashStateOverSizeLimit {
		t.Errorf("hash_state = %q, want %q", got, HashStateOverSizeLimit)
	}
	if _, ok := a.Attributes[execAttrSHA256]; ok {
		t.Error("a file over the cap carries a digest")
	}
	if !execWarning(res, DiagExecutableOverSizeLimit, strconv.FormatInt(ExecutableMaxFileBytes, 10)) {
		t.Errorf("no %s diagnostic names the limit", DiagExecutableOverSizeLimit)
	}
	// Outside the roots and a path that does not exist: no artifact, one
	// diagnostic each, and the diagnostic names the file.
	for _, p := range []string{outside, "/usr/bin/absent"} {
		if execHasArtifact(res, ExecutableArtifactID(p)) {
			t.Errorf("%s produced an artifact although it was refused", p)
		}
		if !execWarning(res, DiagExecutableRefused, p) {
			t.Errorf("no %s diagnostic names %s", DiagExecutableRefused, p)
		}
	}
	set := execArtifact(t, res, ArtifactExecutables)
	if got := set.Attributes[execAttrRefusedCount]; got != "2" {
		t.Errorf("refused_count = %q, want 2", got)
	}
	if got := set.Attributes[execAttrTooLargeCount]; got != "1" {
		t.Errorf("over_size_limit_count = %q, want 1", got)
	}
	if got := set.Attributes[execAttrProgramCount]; got != "2" {
		t.Errorf("program_count = %q, want 2", got)
	}
}

// The file count cap: the programs beyond it are named, not silently dropped,
// and the set artifact says the list is cut.
func TestExecutablesCollectFileCountCap(t *testing.T) {
	const over = 3
	tree := map[string]execTestFile{}
	unitPaths := map[string]string{}
	for i := 0; i < ExecutableMaxFiles+over; i++ {
		p := fmt.Sprintf("/usr/local/bin/agent-%03d", i)
		tree[p] = execTestFile{Content: "agent " + strconv.Itoa(i)}
		unitPaths[fmt.Sprintf("agent-%03d.service", i)] = p
	}
	reader, _ := execTestTree(t, tree)
	units := netSortedKeys(unitPaths)
	states := map[string]string{}
	for u := range unitPaths {
		states[u] = "enabled"
	}
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execUnitFileList(states)}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")})
	// The show call is batched at systemdShowBatch units.
	for i := 0; i < len(units); i += systemdShowBatch {
		end := i + systemdShowBatch
		if end > len(units) {
			end = len(units)
		}
		batch := units[i:end]
		answer := map[string]string{}
		for _, u := range batch {
			answer[u] = unitPaths[u]
		}
		runner.Script(systemctlExe, execShowArgs(batch...), probe.FakeResponse{Stdout: execShowAnswer(answer)})
	}
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial: more programs than the cap allows", res.Status)
	}
	set := execArtifact(t, res, ArtifactExecutables)
	if got := set.Attributes[execAttrProgramCount]; got != strconv.Itoa(ExecutableMaxFiles) {
		t.Fatalf("program_count = %q, want the cap %d", got, ExecutableMaxFiles)
	}
	if got := set.Attributes[execAttrListTruncated]; got != "true" {
		t.Fatalf("program_list_truncated = %q", got)
	}
	// The three programs beyond the cap are the last three by path, and each
	// one is named.
	for i := ExecutableMaxFiles; i < ExecutableMaxFiles+over; i++ {
		p := fmt.Sprintf("/usr/local/bin/agent-%03d", i)
		if execHasArtifact(res, ExecutableArtifactID(p)) {
			t.Errorf("%s was inspected although it is beyond the cap", p)
		}
		if !execWarning(res, DiagExecutableCountCapped, p) {
			t.Errorf("no %s diagnostic names %s", DiagExecutableCountCapped, p)
		}
	}
}

// A symlink that leaves the roots is refused, reported, and nothing of it is
// read. The unowned program of the bastion is the shape behind this: a link
// under /usr/local/bin can point anywhere.
func TestExecutablesCollectSymlinkEscape(t *testing.T) {
	const wrapper = "/usr/local/bin/agent"
	reader, _ := execTestTree(t, map[string]execTestFile{
		// The account name of a home path is one the name gate allows
		// (scripts/check-no-real-names.sh): a persona, never a real account.
		wrapper:                 {Link: "/home/alice/bin/agent"},
		"/home/alice/bin/agent": {Content: "agent bytes"},
	})
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execUnitFileList(map[string]string{"agent.service": "enabled"})}).
		Script(systemctlExe, execShowArgs("agent.service"),
			probe.FakeResponse{Stdout: execShowAnswer(map[string]string{"agent.service": wrapper})}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial", res.Status)
	}
	if execHasArtifact(res, ExecutableArtifactID(wrapper)) {
		t.Error("the refused link produced an artifact")
	}
	if !execWarning(res, DiagExecutableRefused, "home directory") {
		t.Errorf("no diagnostic says the link leads into a home directory: %+v", res.Warnings)
	}
	set := execArtifact(t, res, ArtifactExecutables)
	if got := set.Attributes[execAttrProgramCount]; got != "0" {
		t.Fatalf("program_count = %q, want 0", got)
	}
	// An empty result is a stated fact and not an absence of records.
	if got := set.Attributes[execAttrCandidateCount]; got != "1" {
		t.Fatalf("candidate_path_count = %q, want 1", got)
	}
}

// A file the account may not read has no digest, and only that file is
// affected.
func TestExecutablesCollectUnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a mode of 0000 does not deny a read on windows, so the case cannot be built here")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: a mode of 0000 denies nothing, so the case cannot be built here")
	}
	const (
		closed = "/usr/local/bin/closed"
		open   = "/usr/local/bin/open"
	)
	reader, _ := execTestTree(t, map[string]execTestFile{
		closed: {Content: "secret", Unreadable: true},
		open:   {Content: "readable"},
	})
	unitPaths := map[string]string{"a-closed.service": closed, "b-open.service": open}
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execUnitFileList(map[string]string{"a-closed.service": "enabled", "b-open.service": "enabled"})}).
		Script(systemctlExe, execShowArgs("a-closed.service", "b-open.service"),
			probe.FakeResponse{Stdout: execShowAnswer(unitPaths)}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")}).
		Script(ExecutablesToolStat, execStatArgs(closed, open), probe.FakeResponse{Stdout: []byte(
			closed + " 0 root root 6\n" + open + " 755 root root 8\n")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(closed, open), probe.FakeResponse{
			ExitCode: 1,
			Stderr: []byte("dpkg-query: no path found matching pattern " + closed +
				"\ndpkg-query: no path found matching pattern " + open + "\n"),
		})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial", res.Status)
	}
	a := execArtifact(t, res, ExecutableArtifactID(closed))
	if got := a.Attributes[execAttrHashState]; got != HashStatePermissionDenied {
		t.Errorf("hash_state = %q, want %q", got, HashStatePermissionDenied)
	}
	if _, ok := a.Attributes[execAttrSHA256]; ok {
		t.Error("an unreadable file carries a digest")
	}
	// The metadata of the unreadable file was still read: the mode is the
	// finding that explains the refusal.
	if got := a.Attributes[execAttrMode]; got != "0000" {
		t.Errorf("mode = %q, want 0000", got)
	}
	b := execArtifact(t, res, ExecutableArtifactID(open))
	if b.Attributes[execAttrHashState] != HashStateCaptured || b.Attributes[execAttrSHA256] == "" {
		t.Errorf("the readable file beside it has no digest: %v", b.Attributes)
	}
	if !execWarning(res, DiagExecutableUnreadable, closed) {
		t.Errorf("no %s diagnostic names %s", DiagExecutableUnreadable, closed)
	}
}

// A missing tool is a named gap and never a silent empty result (playbook L1).
func TestExecutablesCollectMissingTools(t *testing.T) {
	t.Run("no systemctl", func(t *testing.T) {
		reader, _ := execTestTree(t, map[string]execTestFile{"/usr/bin/prog": {Content: "x"}})
		runner := probe.NewFakeRunner().
			AddTool(ListenersTool, "/usr/sbin/ss").
			Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")})
		cc, _ := netTestCollect(ExecutablesProbeID, runner)
		res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)
		if res.Status != trustfreeze.StatusPartial {
			t.Fatalf("status %q, want partial", res.Status)
		}
		if !execWarning(res, DiagExecutableSourceMissing, systemctlExe) {
			t.Errorf("no diagnostic names the missing %s: %+v", systemctlExe, res.Warnings)
		}
	})
	t.Run("no dpkg", func(t *testing.T) {
		const p = "/usr/local/bin/agent"
		reader, _ := execTestTree(t, map[string]execTestFile{p: {Content: "agent"}})
		runner := probe.NewFakeRunner().
			AddTool(systemctlExe, "/usr/bin/systemctl").
			AddTool(ListenersTool, "/usr/sbin/ss").
			AddTool(ExecutablesToolStat, "/usr/bin/stat").
			Script(ExecutablesToolStat, []string{"--version"}, probe.FakeResponse{Stdout: execFixture(t, "stat-version.txt")}).
			Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
				probe.FakeResponse{Stdout: execUnitFileList(map[string]string{"agent.service": "enabled"})}).
			Script(systemctlExe, execShowArgs("agent.service"),
				probe.FakeResponse{Stdout: execShowAnswer(map[string]string{"agent.service": p})}).
			Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")}).
			Script(ExecutablesToolStat, execStatArgs(p), probe.FakeResponse{Stdout: []byte(p + " 755 root root 5\n")})
		cc, _ := netTestCollect(ExecutablesProbeID, runner)
		res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)
		a := execArtifact(t, res, ExecutableArtifactID(p))
		// Unknown is not the same statement as unowned (T-03b B4).
		if got := a.Attributes[execAttrPackageOwner]; got != PackageOwnerUnknown {
			t.Errorf("package_owner = %q, want %q", got, PackageOwnerUnknown)
		}
		if got := a.Attributes[execAttrPackageSource]; got != PackageSourceDpkgUnavailable {
			t.Errorf("package_owner_source = %q", got)
		}
		if a.Attributes[execAttrSHA256] == "" {
			t.Error("the digest is missing although the file was readable")
		}
		if res.Status != trustfreeze.StatusPartial {
			t.Fatalf("status %q, want partial", res.Status)
		}
	})
	t.Run("no stat", func(t *testing.T) {
		const p = "/usr/local/bin/agent"
		reader, _ := execTestTree(t, map[string]execTestFile{p: {Content: "agent"}})
		runner := probe.NewFakeRunner().
			AddTool(systemctlExe, "/usr/bin/systemctl").
			AddTool(ListenersTool, "/usr/sbin/ss").
			AddTool(ExecutablesToolDpkg, "/usr/bin/dpkg").
			Script(ExecutablesToolDpkg, []string{"--version"}, probe.FakeResponse{Stdout: execFixture(t, "dpkg-version.txt")}).
			Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
				probe.FakeResponse{Stdout: execUnitFileList(map[string]string{"agent.service": "enabled"})}).
			Script(systemctlExe, execShowArgs("agent.service"),
				probe.FakeResponse{Stdout: execShowAnswer(map[string]string{"agent.service": p})}).
			Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")}).
			Script(ExecutablesToolDpkg, execDpkgArgs(p), probe.FakeResponse{Stdout: []byte("vendor-agent: " + p + "\n")})
		cc, _ := netTestCollect(ExecutablesProbeID, runner)
		res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)
		a := execArtifact(t, res, ExecutableArtifactID(p))
		// Without stat there is no mode and no owner, and the size is the
		// number of bytes the hash read.
		if _, ok := a.Attributes[execAttrMode]; ok {
			t.Error("a mode was recorded although stat was not asked")
		}
		if got := a.Attributes[execAttrSize]; got != "5" {
			t.Errorf("size = %q, want the 5 bytes the hash read", got)
		}
		if got := a.Attributes[execAttrPackageOwner]; got != "vendor-agent" {
			t.Errorf("package_owner = %q", got)
		}
		if !execWarning(res, probe.DiagFieldUnavailable, ExecutablesToolStat) {
			t.Errorf("no diagnostic names the missing %s", ExecutablesToolStat)
		}
	})
}

// The size of a program is the number of bytes that produced its digest. Where
// stat answered something else, the file was written between the two reads and
// the difference is stated instead of silently resolved.
func TestExecutablesCollectFileChangedBetweenReads(t *testing.T) {
	const p = "/usr/local/bin/agent"
	reader, _ := execTestTree(t, map[string]execTestFile{p: {Content: "agent bytes"}})
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execUnitFileList(map[string]string{"agent.service": "enabled"})}).
		Script(systemctlExe, execShowArgs("agent.service"),
			probe.FakeResponse{Stdout: execShowAnswer(map[string]string{"agent.service": p})}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")}).
		// The measured stat line shape with a size the file does not have,
		// which is what a program replaced during the capture looks like.
		Script(ExecutablesToolStat, execStatArgs(p), probe.FakeResponse{Stdout: []byte(p + " 755 root root 999\n")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(p), probe.FakeResponse{
			ExitCode: 1,
			Stderr:   []byte("dpkg-query: no path found matching pattern " + p + "\n"),
		})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	a := execArtifact(t, res, ExecutableArtifactID(p))
	if got := a.Attributes[execAttrSize]; got != "11" {
		t.Errorf("size = %q, want the 11 bytes the hash read", got)
	}
	if a.Attributes[execAttrHashState] != HashStateCaptured {
		t.Errorf("hash_state = %q", a.Attributes[execAttrHashState])
	}
	if !execWarning(res, DiagExecutableChangedWhileRead, p) {
		t.Errorf("no %s diagnostic names %s: %+v", DiagExecutableChangedWhileRead, p, res.Warnings)
	}
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial", res.Status)
	}
}

// A process that listens and runs a program outside the roots is a finding of
// its own, and it is not the same statement as a link that could not be read.
func TestExecutablesCollectListenerProgramRefused(t *testing.T) {
	reader, _ := execTestTree(t, map[string]execTestFile{
		"/home/alice/bin/agent": {Content: "agent bytes"},
		"/proc/2698/exe":        {Link: "/home/alice/bin/agent"},
	})
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: []byte("")}).
		Script(ListenersTool, []string{"-H", "-lntup"},
			probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-H-lntup.txt")})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial", res.Status)
	}
	if !execWarning(res, DiagExecutableRefused, "home directory") {
		t.Errorf("no %s diagnostic says the program lies under a home directory: %+v", DiagExecutableRefused, res.Warnings)
	}
	set := execArtifact(t, res, ArtifactExecutables)
	if got := set.Attributes[execAttrProgramCount]; got != "0" {
		t.Errorf("program_count = %q, want 0", got)
	}
	if got := set.Attributes[execAttrRefusedCount]; got != "1" {
		t.Errorf("refused_count = %q, want 1", got)
	}
	// The pid of the process is volatile and appears nowhere.
	for _, w := range res.Warnings {
		if strings.Contains(w.Message, "2698") {
			t.Errorf("a diagnostic carries a pid: %q", w.Message)
		}
	}
}

// A host that names no program at all is captured with an empty result, and the
// set artifact says so: an empty answer is a recorded fact and not an absence
// of records (playbook L1).
func TestExecutablesCollectGenuinelyEmpty(t *testing.T) {
	reader, _ := execTestTree(t, map[string]execTestFile{})
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: []byte("")}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, reason %q, want captured", res.Status, res.Reason)
	}
	set := execArtifact(t, res, ArtifactExecutables)
	for k, want := range map[string]string{
		execAttrProgramCount:   "0",
		execAttrCandidateCount: "0",
		execAttrHashedCount:    "0",
		execAttrRefusedCount:   "0",
	} {
		if got := set.Attributes[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if len(res.NormalizedState) != 1 {
		t.Fatalf("%d artifacts, want the set artifact only", len(res.NormalizedState))
	}
	// Neither stat nor dpkg was called: there was nothing to ask about.
	for _, call := range runner.Calls() {
		if call.Executable == ExecutablesToolStat || call.Executable == ExecutablesToolDpkg {
			t.Errorf("%s was called although no program was named", call.Executable)
		}
	}
}

// A unit that starts a program through a symlink: the artifact is the file the
// bytes are in, the link is recorded beside it, and the package question is
// asked about the RESOLVED path.
//
// The last part is the measured lesson of this tool: "dpkg -S /bin/ls" answers
// that no path matches, because the database holds /usr/bin/ls and /bin is a
// symlink to /usr/bin on a merged-usr Ubuntu (testdata/executables/README.md).
// A probe that asks before it resolves reports half the programs of the host as
// owned by nobody.
func TestExecutablesCollectResolvesBeforeAsking(t *testing.T) {
	const (
		link   = "/usr/local/bin/wrapper"
		target = "/usr/bin/prog"
	)
	reader, _ := execTestTree(t, map[string]execTestFile{
		target: {Content: "program bytes"},
		link:   {Link: target},
	})
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execUnitFileList(map[string]string{"wrapper.service": "enabled"})}).
		Script(systemctlExe, execShowArgs("wrapper.service"),
			probe.FakeResponse{Stdout: execShowAnswer(map[string]string{"wrapper.service": link})}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")}).
		Script(ExecutablesToolStat, execStatArgs(target), probe.FakeResponse{Stdout: []byte(target + " 755 root root 13\n")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(target), probe.FakeResponse{Stdout: []byte("vendor-agent: " + target + "\n")})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q, reason %q, warnings %+v", res.Status, res.Reason, res.Warnings)
	}
	if execHasArtifact(res, ExecutableArtifactID(link)) {
		t.Errorf("the link got an artifact of its own")
	}
	a := execArtifact(t, res, ExecutableArtifactID(target))
	if got := a.Attributes[execAttrPath]; got != target {
		t.Errorf("path = %q, want the resolved %q", got, target)
	}
	if got := a.Attributes[execAttrRequestedPath]; got != link {
		t.Errorf("requested_path = %q, want %q", got, link)
	}
	if got := a.Attributes[execAttrPackageOwner]; got != "vendor-agent" {
		t.Errorf("package_owner = %q", got)
	}
	if got := a.Attributes[execAttrUnits]; got != "wrapper.service" {
		t.Errorf("units = %q", got)
	}
	// The tools were asked about the resolved path and never about the link.
	for _, call := range runner.Calls() {
		for _, arg := range call.Args {
			if arg == link {
				t.Errorf("%s was asked about the link: %v", call.Executable, call.Args)
			}
		}
	}
}

// F1 for this probe: a socket list the output cap cut must never be reported as
// captured, and the diagnostic must name the stream and the cap. The helpers of
// findings_test.go build the oversized answer and check the shape.
func TestExecutablesProbeTruncatedListingIsPartial(t *testing.T) {
	reader, _ := execTestTree(t, map[string]execTestFile{})
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: []byte("")}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: tfSSLines(400)})
	cc, _ := tfLimitedCollect(ExecutablesProbeID, runner, probe.FakeFiles{}, probe.Limits{MaxStdoutBytes: tfCap})
	res := NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q over a cut socket list, want partial (reason %q)", res.Status, res.Reason)
	}
	tfTruncationDiagnostic(t, res, "stdout")
	set := execArtifact(t, res, ArtifactExecutables)
	if set.Attributes[execAttrListTruncated] != "true" {
		t.Fatalf("the set artifact claims a complete list over a cut answer: %v", set.Attributes)
	}
}

// The reader names the roots it may open, so a caller can print the scope.
func TestRootedProgramReaderRoots(t *testing.T) {
	got := DefaultProgramReader().Roots()
	for _, want := range ExecutableRoots() {
		if !slices.Contains(got, want) {
			t.Fatalf("the reader does not hold the root %q: %v", want, got)
		}
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("the roots are not sorted: %v", got)
	}
}

// ---------------------------------------------------------------------------
// Bounds of the work itself, not only of the result (review of T-03b).
// ---------------------------------------------------------------------------

// execCountingReader wraps a ProgramReader and counts what the probe asked it
// for. It is the instrument of the two tests below: a bound on the WORK cannot
// be measured on the result, only on the number of calls the probe made.
type execCountingReader struct {
	inner ProgramReader
	// resolved and processLinks count the two calls that cost a syscall per
	// candidate path.
	resolved     int
	processLinks int
	hashed       int
	// hashedPaths and resolvedPaths record WHAT was asked for, so a test can
	// check the claim that nothing outside the roots is opened.
	hashedPaths   []string
	resolvedPaths []string
	// cancelAfterHash cancels ctx once this many files have been hashed, which
	// is what a deadline reached in the middle of a capture does.
	cancelAfterHash int
	cancel          context.CancelFunc
}

func (r *execCountingReader) Resolve(p string) (string, error) {
	r.resolved++
	r.resolvedPaths = append(r.resolvedPaths, p)
	return r.inner.Resolve(p)
}

func (r *execCountingReader) ProcessExecutable(pid string) (string, error) {
	r.processLinks++
	return r.inner.ProcessExecutable(pid)
}

func (r *execCountingReader) Hash(ctx context.Context, p string, maxBytes int64) (string, int64, error) {
	if r.cancel != nil && r.hashed == r.cancelAfterHash {
		// Cancel BEFORE delegating, so the production hash loop sees the
		// cancelled context exactly where a real deadline would hit it.
		r.cancel()
	}
	r.hashed++
	r.hashedPaths = append(r.hashedPaths, p)
	return r.inner.Hash(ctx, p, maxBytes)
}

// The candidate cap bounds the work BEFORE it happens: a host that names more
// paths than ExecutableMaxCandidates performs at most that many resolutions,
// and the paths beyond the cap are named rather than dropped in silence.
//
// The file count cap (TestExecutablesCollectFileCountCap) cannot do this job.
// It applies to the files that came OUT of the resolution, so with it alone the
// number of EvalSymlinks calls is whatever the sources happen to name: 512
// units that may each carry several ExecStart paths, plus one per listening
// process. This test measures the calls, not the artifacts.
func TestExecutablesCandidateCapBoundsResolutionBeforeIt(t *testing.T) {
	const over = 3
	const perUnit = 3
	// No file exists on disk under the candidate paths: every candidate is
	// refused AFTER it was resolved, which is exactly the case where a cap on
	// the surviving files bounds no work at all.
	reader, _ := execTestTree(t, map[string]execTestFile{
		"/usr/bin/present": {Content: "present"},
	})
	counting := &execCountingReader{inner: reader}
	// A unit may start several programs, so the candidate count is not bounded
	// by the unit selection cap: here three ExecStart paths per unit reach
	// beyond the candidate cap with far fewer units than systemdMaxShowUnits.
	unitPaths := map[string][]string{}
	for i := 0; len(unitPaths)*perUnit < ExecutableMaxCandidates+over-1; i++ {
		unit := fmt.Sprintf("agent-%04d.service", i)
		var paths []string
		for k := 0; k < perUnit; k++ {
			paths = append(paths, fmt.Sprintf("/usr/local/bin/agent-%04d-%d", i, k))
		}
		unitPaths[unit] = paths
	}
	unitPaths["tail.service"] = []string{"/usr/local/bin/tail-program"}
	var candidates int
	for _, v := range unitPaths {
		candidates += len(v)
	}
	if candidates != ExecutableMaxCandidates+over {
		t.Fatalf("this test builds %d candidate path(s), it needs %d", candidates, ExecutableMaxCandidates+over)
	}
	if len(unitPaths) >= systemdMaxShowUnits {
		t.Fatalf("this test needs fewer units (%d) than the selection cap (%d), or it would measure that cap instead",
			len(unitPaths), systemdMaxShowUnits)
	}
	units := netSortedKeys(unitPaths)
	states := map[string]string{}
	for u := range unitPaths {
		states[u] = "enabled"
	}
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execUnitFileList(states)}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")})
	for i := 0; i < len(units); i += systemdShowBatch {
		end := i + systemdShowBatch
		if end > len(units) {
			end = len(units)
		}
		batch := units[i:end]
		answer := map[string][]string{}
		for _, u := range batch {
			answer[u] = unitPaths[u]
		}
		runner.Script(systemctlExe, execShowArgs(batch...), probe.FakeResponse{Stdout: execShowAnswerMulti(answer)})
	}
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(counting).Collect(context.Background(), cc)

	if counting.resolved > ExecutableMaxCandidates {
		t.Errorf("the probe resolved %d candidate path(s) with a cap of %d: the resolution is not bounded",
			counting.resolved, ExecutableMaxCandidates)
	}
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial: candidate paths were dropped", res.Status)
	}
	set := execArtifact(t, res, ArtifactExecutables)
	if got := set.Attributes[execAttrCandidateCount]; got != strconv.Itoa(ExecutableMaxCandidates) {
		t.Errorf("candidate_path_count = %q, want the cap %d", got, ExecutableMaxCandidates)
	}
	if got := set.Attributes[execAttrCandidateDropped]; got != strconv.Itoa(over) {
		t.Errorf("candidate_paths_dropped = %q, want %d", got, over)
	}
	if !execWarning(res, DiagExecutableCandidateCapped, strconv.Itoa(ExecutableMaxCandidates)) {
		t.Errorf("no %s diagnostic names the cap", DiagExecutableCandidateCapped)
	}
	var named int
	for _, w := range res.Warnings {
		if w.Code == DiagExecutableCandidateCapped {
			named++
		}
	}
	if named == 0 {
		t.Error("the candidate cap dropped paths without one diagnostic naming any of them")
	}
}

// execShowAnswerMulti is execShowAnswer for units that start several programs:
// one ExecStart line per path, in the block shape of the measured fixture.
func execShowAnswerMulti(unitToPaths map[string][]string) []byte {
	var b strings.Builder
	for _, unit := range netSortedKeys(unitToPaths) {
		for _, p := range unitToPaths[unit] {
			fmt.Fprintf(&b, "ExecStart={ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n", p, p)
		}
		fmt.Fprintf(&b, "Id=%s\n\n", unit)
	}
	return []byte(b.String())
}

// A capture that runs out of time says so. It must never report the files it
// did not reach as unreadable, because unreadable is a property of a FILE this
// account could not read, and a file nobody tried to read has no such property.
func TestExecutablesTimeoutIsNotAnUnreadableFile(t *testing.T) {
	programs := map[string]string{
		"a.service": "/usr/local/bin/a",
		"b.service": "/usr/local/bin/b",
		"c.service": "/usr/local/bin/c",
	}
	tree := map[string]execTestFile{}
	for _, p := range programs {
		tree[p] = execTestFile{Content: "bytes of " + p}
	}
	paths := netSortedKeys(tree)
	units := netSortedKeys(programs)
	states := map[string]string{}
	for u := range programs {
		states[u] = "enabled"
	}

	for _, tc := range []struct {
		name string
		// after is how many files are hashed before the deadline lands.
		after int
	}{
		{"the deadline lands inside the first file", 0},
		{"the deadline lands after the first file", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, _ := execTestTree(t, tree)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			counting := &execCountingReader{inner: reader, cancelAfterHash: tc.after, cancel: cancel}
			runner := execRunner(t).
				Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
					probe.FakeResponse{Stdout: execUnitFileList(states)}).
				Script(systemctlExe, execShowArgs(units...), probe.FakeResponse{Stdout: execShowAnswer(programs)}).
				Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte("")}).
				Script(ExecutablesToolStat, execStatArgs(paths...), probe.FakeResponse{
					Stdout: []byte(fmt.Sprintf("%s 755 root root 12\n%s 755 root root 12\n%s 755 root root 12\n",
						paths[0], paths[1], paths[2]))})
			cc, _ := netTestCollect(ExecutablesProbeID, runner)
			res := NewExecutablesProbeWithReader(counting).Collect(ctx, cc)

			if res.Status != trustfreeze.StatusTimeout {
				t.Fatalf("status %q, want timeout (reason %q)", res.Status, res.Reason)
			}
			if res.Error == nil || res.Error.Class != probe.ClassTimeout {
				t.Errorf("probe error %v, want a timeout class", res.Error)
			}
			var notRead, unreadable, captured int
			for _, a := range res.NormalizedState {
				switch a.Attributes[execAttrHashState] {
				case HashStateNotRead:
					notRead++
					if a.Attributes[execAttrSHA256] != "" {
						t.Errorf("%s carries a digest although it was not read", a.ID)
					}
				case HashStateUnreadable:
					unreadable++
				case HashStateCaptured:
					captured++
				}
			}
			if unreadable != 0 {
				t.Errorf("%d program(s) are reported as unreadable although the capture ran out of time", unreadable)
			}
			if want := len(programs) - tc.after; notRead != want {
				t.Errorf("hash_state not_read on %d program(s), want %d", notRead, want)
			}
			if captured != tc.after {
				t.Errorf("hash_state captured on %d program(s), want %d", captured, tc.after)
			}
			if !execWarning(res, probe.DiagFieldTimeout, "ran out of time") {
				t.Errorf("no timeout diagnostic names the cause; warnings %v", res.Warnings)
			}
		})
	}
}

// execBastionCollect runs the probe over the measured bastion scenario of
// TestExecutablesCollectUnownedProgram: one program that a unit starts and that
// holds a listening socket, and that no package owns.
func execBastionCollect(t *testing.T) trustfreeze.ProbeResult {
	t.Helper()
	const ngrok = "/usr/local/bin/ngrok"
	reader, _ := execTestTree(t, map[string]execTestFile{
		ngrok:            {Size: 32911522},
		"/proc/2698/exe": {Link: ngrok},
	})
	runner := execRunner(t).
		Script(ExecutablesToolStat, []string{"--version"}, probe.FakeResponse{Stdout: execFixture(t, "stat-version-2204.txt")}).
		Script(ExecutablesToolDpkg, []string{"--version"}, probe.FakeResponse{Stdout: execFixture(t, "dpkg-version-2204.txt")}).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execFixture(t, "systemctl-list-unit-files-subset-2204.txt")}).
		Script(systemctlExe, execShowArgs("ngrok-host-a.service", "ssh.socket"),
			probe.FakeResponse{Stdout: execFixture(t, "systemctl-show-execstart-2204.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"},
			probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-H-lntup.txt")}).
		Script(ExecutablesToolStat, execStatArgs(ngrok),
			probe.FakeResponse{Stdout: []byte("/usr/local/bin/ngrok 755 root root 32911522\n")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(ngrok), probe.FakeResponse{
			ExitCode: 1,
			Stderr:   execFixture(t, "dpkg-search-2204.stderr.txt"),
		})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	return NewExecutablesProbeWithReader(reader).Collect(context.Background(), cc)
}

// Every attribute of an executable artifact is classified: either this capture
// OBSERVED it on this host, or it is what the package database CLAIMS about the
// path (review of T-03b, finding 2).
//
// The artifact State is observed, which is true of the file properties and the
// digest. It is not true of package_owner and diverted_by: those are answers of
// a database about a path, and this build never verifies a file against its
// package, so an owned path is no statement about the bytes. The set artifact
// says that in the bundle (package_contents_verified), not only in the manual,
// and this test fails when a new attribute appears that nobody classified.
func TestExecutableAttributesSayObservedOrClaimed(t *testing.T) {
	observed := []string{
		execAttrPath, execAttrRequestedPath, execAttrSize, execAttrMode,
		execAttrOwner, execAttrGroup, execAttrSHA256, execAttrHashState,
		execAttrOrigins, execAttrUnits, execAttrUnitCount,
	}
	claimed := []string{execAttrPackageOwner, execAttrPackageSource, execAttrDivertedBy}

	res := execBastionCollect(t)
	var seen int
	for _, a := range res.NormalizedState {
		if a.Type != artifactTypeExecutable {
			continue
		}
		seen++
		if a.State != trustfreeze.StateObserved {
			t.Errorf("%s is %q; the file properties of a program are observed", a.ID, a.State)
		}
		for k := range a.Attributes {
			if !slices.Contains(observed, k) && !slices.Contains(claimed, k) {
				t.Errorf("%s carries the attribute %q, which is in neither list: an attribute of an observed artifact is either an observation of this host or a claim of the package database, and a reader has to be told which", a.ID, k)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no executable artifact, so this test measures nothing")
	}
	set := execArtifact(t, res, ArtifactExecutables)
	if got := set.Attributes[execAttrPackageVerified]; got != "false" {
		t.Errorf("%s = %q, want false: this build runs no package verification, and a bundle that does not say so leaves package_owner to be read as a statement about the bytes",
			execAttrPackageVerified, got)
	}
	// The claim attributes really are the ones the package database answered
	// for: the unowned program of the bastion is the case that proves it.
	var withClaim int
	for _, a := range res.NormalizedState {
		if a.Type != artifactTypeExecutable {
			continue
		}
		if a.Attributes[execAttrPackageSource] != "" {
			withClaim++
		}
	}
	if withClaim != seen {
		t.Errorf("%d of %d program artifacts name the source of their package answer; every one has to, or unknown and unowned cannot be told apart", withClaim, seen)
	}
}

// The docstring of executables.go says an allowlist of roots decides what is
// opened, and names /proc/<pid>/exe as the one path outside them. This test is
// that sentence: every file the probe OPENS lies under ExecutableRoots, and the
// /proc link is read as a LINK (a readlink), never opened and never hashed.
//
// Without the exception in the docstring the claim would be wider than the code
// (review of T-03b, finding 4); without this test the docstring would be the
// only place either half is stated.
func TestExecutablesOpensNothingOutsideTheRootsAndReadsProcAsALink(t *testing.T) {
	const ngrok = "/usr/local/bin/ngrok"
	reader, _ := execTestTree(t, map[string]execTestFile{
		ngrok:            {Content: "program bytes"},
		"/proc/2698/exe": {Link: ngrok},
	})
	counting := &execCountingReader{inner: reader}
	runner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: []byte("")}).
		Script(ListenersTool, []string{"-H", "-lntup"},
			probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-H-lntup.txt")}).
		Script(ExecutablesToolStat, execStatArgs(ngrok),
			probe.FakeResponse{Stdout: []byte("/usr/local/bin/ngrok 755 root root 13\n")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(ngrok), probe.FakeResponse{
			ExitCode: 1,
			Stderr:   execFixture(t, "dpkg-search-2204.stderr.txt"),
		})
	cc, _ := netTestCollect(ExecutablesProbeID, runner)
	res := NewExecutablesProbeWithReader(counting).Collect(context.Background(), cc)

	if counting.processLinks == 0 {
		t.Fatal("the probe read no /proc/<pid>/exe link, so this test measures nothing")
	}
	if len(counting.hashedPaths) == 0 {
		t.Fatalf("the probe hashed nothing; status %q, reason %q", res.Status, res.Reason)
	}
	for _, p := range counting.hashedPaths {
		if strings.HasPrefix(p, "/proc/") {
			t.Errorf("the probe opened %q: /proc/<pid>/exe is read as a link, never opened", p)
		}
		var inRoot bool
		for _, root := range ExecutableRoots() {
			if p == root || strings.HasPrefix(p, root+"/") {
				inRoot = true
			}
		}
		if !inRoot {
			t.Errorf("the probe opened %q, which is under none of the roots %v", p, ExecutableRoots())
		}
	}
	// The path that came out of the link is the program, and it is what was
	// hashed: the link target goes through the same rules as every candidate.
	if !slices.Contains(counting.hashedPaths, ngrok) {
		t.Errorf("hashed paths %v do not carry the program behind the listening socket", counting.hashedPaths)
	}
}
