package common

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// winFixture is one export of the CurrentVersion key in testdata/windows, in
// the format of `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"`.
type winFixture struct {
	file string
	// origin: "reconstructed" is a value set written from public Microsoft
	// release data for that build, not captured from a machine; "synthetic"
	// is a reconstructed set changed on purpose. No fixture is a capture.
	origin  string
	want    OSInfo
	derived []string
}

var winFixtures = []winFixture{
	{"win11-23h2-pro.txt", "reconstructed", OSInfo{Name: "Windows 11 Pro", Version: "23H2", Build: "22631.4169"}, []string{AttrOSName}},
	{"win11-24h2-enterprise.txt", "reconstructed", OSInfo{Name: "Windows 11 Enterprise", Version: "24H2", Build: "26100.2033"}, []string{AttrOSName}},
	{"win10-22h2-enterprise.txt", "reconstructed", OSInfo{Name: "Windows 10 Enterprise", Version: "22H2", Build: "19045.4894"}, nil},
	{"server2022-datacenter.txt", "reconstructed", OSInfo{Name: "Windows Server 2022 Datacenter", Version: "21H2", Build: "20348.2700"}, nil},
	{"server2025-datacenter.txt", "reconstructed", OSInfo{Name: "Windows Server 2025 Datacenter", Version: "24H2", Build: "26100.2033"}, nil},
	{"win10-1809-ltsc-2019.txt", "reconstructed", OSInfo{Name: "Windows 10 Enterprise LTSC 2019", Version: "1809", Build: "17763.6293"}, []string{AttrOSVersion}},
	{"win11-23h2-missing-ubr.txt", "synthetic", OSInfo{Name: "Windows 11 Pro", Version: "23H2", Build: "22631"}, []string{AttrOSName}},
}

// winRegQuery parses reg query output (LF or CRLF) into the value set the
// registry reader returns for the same key.
func winRegQuery(t *testing.T, b []byte) map[string]winRegValue {
	t.Helper()
	typeCode := map[string]uint32{}
	for code, name := range winRegTypeNames {
		typeCode[name] = code
	}
	values := map[string]winRegValue{}
	header := false
	for i, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rest, ok := strings.CutPrefix(line, "    ")
		if !ok {
			if line != `HKEY_LOCAL_MACHINE\`+winCurrentVersionSubkey {
				t.Fatalf("line %d: unexpected key %q", i+1, line)
			}
			header = true
			continue
		}
		parts := strings.SplitN(rest, "    ", 3)
		if len(parts) < 2 {
			t.Fatalf("line %d: no type in %q", i+1, line)
		}
		code, ok := typeCode[parts[1]]
		if !ok {
			t.Fatalf("line %d: unknown type %q", i+1, parts[1])
		}
		data := ""
		if len(parts) == 3 {
			data = parts[2]
		}
		v := winRegValue{Type: code}
		switch code {
		case winRegSZ, winRegExpandSZ:
			v.Str = data
		case winRegDWORD, winRegQWORD:
			hex, ok := strings.CutPrefix(data, "0x")
			n, err := strconv.ParseUint(hex, 16, 64)
			if !ok || err != nil {
				t.Fatalf("line %d: bad integer %q", i+1, data)
			}
			v.Num = n
		}
		if _, dup := values[parts[0]]; dup {
			t.Fatalf("line %d: value %s twice", i+1, parts[0])
		}
		values[parts[0]] = v
	}
	if !header {
		t.Fatal("no key header")
	}
	return values
}

func winFixtureBytes(t *testing.T, file string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "windows", file))
	if err != nil {
		t.Fatalf("fixture %s: %v", file, err)
	}
	return b
}

// winValuesReader serves a value set the way the registry reader does: the
// error of opening the key, or the mapped values.
type winValuesReader struct {
	values  map[string]winRegValue
	openErr error
}

func (r winValuesReader) Read() (OSInfo, error) {
	v, err := r.readDetail()
	return v.Info, err
}

func (r winValuesReader) readDetail() (windowsVersion, error) {
	if r.openErr != nil {
		return windowsVersion{}, r.openErr
	}
	return windowsVersionFromValues(r.values)
}

// nativeArch answers like the registry reader on an arm64 machine.
func (r winValuesReader) nativeArch() (string, error) { return "arm64", nil }

func winSZ(s string) winRegValue    { return winRegValue{Type: winRegSZ, Str: s} }
func winDWORD(n uint64) winRegValue { return winRegValue{Type: winRegDWORD, Num: n} }

// winDenied is a value that exists but could not be read.
func winDenied(typ uint32) winRegValue {
	return winRegValue{Type: typ, Err: newWinRegError("read value", winErrorAccessDenied, errors.New("Access is denied."))}
}

// winClient returns a Windows 10 22H2 client value set.
func winClient() map[string]winRegValue {
	return map[string]winRegValue{
		winValueCurrentBuild:       winSZ("19045"),
		winValueCurrentBuildNumber: winSZ("19045"),
		winValueDisplayVersion:     winSZ("22H2"),
		winValueEditionID:          winSZ("Enterprise"),
		winValueInstallationType:   winSZ("Client"),
		winValueProductName:        winSZ("Windows 10 Enterprise"),
		winValueReleaseID:          winSZ("2009"),
		winValueUBR:                winDWORD(4894),
	}
}

func winFailedFields(err error) []string {
	var ve *winVersionError
	if !errors.As(err, &ve) {
		return nil
	}
	var out []string
	for _, f := range ve.fields {
		out = append(out, f.Field)
	}
	return out
}

func winDerivedFields(v windowsVersion) []string {
	var out []string
	for k := range v.Derived {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestWinVersionFixtures: every fixture maps to the expected OSInfo, from an
// LF file and from its CRLF form (reg.exe output, and a Windows checkout with
// core.autocrlf), and the raw values stay available for evidence.
func TestWinVersionFixtures(t *testing.T) {
	for _, f := range winFixtures {
		lf := winFixtureBytes(t, f.file)
		for layout, b := range map[string][]byte{
			"lf":   lf,
			"crlf": []byte(strings.ReplaceAll(string(lf), "\n", "\r\n")),
		} {
			values := winRegQuery(t, b)
			got, err := windowsVersionFromValues(values)
			if err != nil {
				t.Fatalf("%s %s: %v", f.file, layout, err)
			}
			if got.Info != f.want {
				t.Fatalf("%s %s: got %+v, want %+v", f.file, layout, got.Info, f.want)
			}
			if d := winDerivedFields(got); !reflect.DeepEqual(d, f.derived) {
				t.Fatalf("%s %s: derived %v (%v), want %v", f.file, layout, d, got.Derived, f.derived)
			}
			if got.Values[winValueProductName] != values[winValueProductName].Str {
				t.Fatalf("%s %s: raw ProductName not kept: %v", f.file, layout, got.Values)
			}
		}
	}
}

// TestWinVersionWindows11Rule: each case flips one condition of the Windows 11
// name rule against the base case (a client reporting "Windows 10 Pro" on
// build 22631), so every condition independently decides the outcome.
func TestWinVersionWindows11Rule(t *testing.T) {
	base := func() map[string]winRegValue {
		v := winClient()
		v[winValueProductName] = winSZ("Windows 10 Pro")
		v[winValueCurrentBuild] = winSZ("22631")
		v[winValueCurrentBuildNumber] = winSZ("22631")
		v[winValueEditionID] = winSZ("Professional")
		return v
	}
	cases := []struct {
		name   string
		mutate func(map[string]winRegValue)
		want   string // "" means os_name must fail
	}{
		{"base: client, Windows 10 name, build 22631", func(map[string]winRegValue) {}, "Windows 11 Pro"},
		{"first Windows 11 build", func(v map[string]winRegValue) { v[winValueCurrentBuild] = winSZ("22000") }, "Windows 11 Pro"},
		{"last build below Windows 11", func(v map[string]winRegValue) { v[winValueCurrentBuild] = winSZ("21999") }, "Windows 10 Pro"},
		{"not a Windows 10 name", func(v map[string]winRegValue) { v[winValueProductName] = winSZ("Windows Server 2025 Datacenter") }, "Windows Server 2025 Datacenter"},
		{"prefix must end at a word", func(v map[string]winRegValue) { v[winValueProductName] = winSZ("Windows 100 Pro") }, "Windows 100 Pro"},
		{"bare Windows 10", func(v map[string]winRegValue) { v[winValueProductName] = winSZ("Windows 10") }, "Windows 11"},
		{"server installation type", func(v map[string]winRegValue) { v[winValueInstallationType] = winSZ("Server Core") }, "Windows 10 Pro"},
		{"nano server installation type", func(v map[string]winRegValue) { v[winValueInstallationType] = winSZ("Nano Server") }, "Windows 10 Pro"},
		{"server edition on a client installation type", func(v map[string]winRegValue) { v[winValueEditionID] = winSZ("ServerStandard") }, "Windows 10 Pro"},
		{"no guard values", func(v map[string]winRegValue) {
			delete(v, winValueInstallationType)
			delete(v, winValueEditionID)
		}, "Windows 11 Pro"},
		{"unreadable guard counts as absent", func(v map[string]winRegValue) { v[winValueInstallationType] = winDenied(winRegSZ) }, "Windows 11 Pro"},
		{"build from CurrentBuildNumber", func(v map[string]winRegValue) { delete(v, winValueCurrentBuild) }, "Windows 11 Pro"},
		{"no build number", func(v map[string]winRegValue) {
			delete(v, winValueCurrentBuild)
			delete(v, winValueCurrentBuildNumber)
		}, ""},
		{"build of the wrong type", func(v map[string]winRegValue) { v[winValueCurrentBuild] = winDWORD(22631) }, ""},
	}
	for _, c := range cases {
		v := base()
		c.mutate(v)
		pn := v[winValueProductName].Str
		got, err := windowsVersionFromValues(v)
		if c.want == "" {
			var ve *winVersionError
			if !errors.As(err, &ve) || ve.Field(AttrOSName) == nil || got.Info.Name != "" {
				t.Fatalf("%s: name %q err %v, want a failed os_name", c.name, got.Info.Name, err)
			}
			continue
		}
		if got.Info.Name != c.want {
			t.Fatalf("%s: name %q, want %q (err %v)", c.name, got.Info.Name, c.want, err)
		}
		if _, derived := got.Derived[AttrOSName]; derived != (c.want != pn) {
			t.Fatalf("%s: derivation recorded %v, renamed %v: %v", c.name, derived, c.want != pn, got.Derived)
		}
	}
}

// TestWinVersionFallbacksAndFailures: a fallback is taken only when the
// preferred value does not exist; a value that exists but cannot be read, or
// has the wrong type, fails its field instead (SPEC-0471 TF06-R2: failed,
// missing and not read are distinct, nothing is invented).
func TestWinVersionFallbacksAndFailures(t *testing.T) {
	std := OSInfo{Name: "Windows 10 Enterprise", Version: "22H2", Build: "19045.4894"}
	with := func(f func(*OSInfo)) OSInfo {
		o := std
		f(&o)
		return o
	}
	cases := []struct {
		name    string
		mutate  func(map[string]winRegValue)
		want    OSInfo
		failed  []string
		derived []string
	}{
		{"base", func(map[string]winRegValue) {}, std, nil, nil},
		{"DisplayVersion absent uses ReleaseId", func(v map[string]winRegValue) { delete(v, winValueDisplayVersion) },
			with(func(o *OSInfo) { o.Version = "2009" }), nil, []string{AttrOSVersion}},
		{"empty DisplayVersion uses ReleaseId", func(v map[string]winRegValue) { v[winValueDisplayVersion] = winSZ("  ") },
			with(func(o *OSInfo) { o.Version = "2009" }), nil, []string{AttrOSVersion}},
		{"denied DisplayVersion does not fall back", func(v map[string]winRegValue) { v[winValueDisplayVersion] = winDenied(winRegSZ) },
			with(func(o *OSInfo) { o.Version = "" }), []string{AttrOSVersion}, nil},
		{"DisplayVersion of the wrong type", func(v map[string]winRegValue) { v[winValueDisplayVersion] = winDWORD(22) },
			with(func(o *OSInfo) { o.Version = "" }), []string{AttrOSVersion}, nil},
		{"no version value is missing, not failed", func(v map[string]winRegValue) {
			delete(v, winValueDisplayVersion)
			delete(v, winValueReleaseID)
		}, with(func(o *OSInfo) { o.Version = "" }), nil, nil},
		{"denied ReleaseId", func(v map[string]winRegValue) {
			delete(v, winValueDisplayVersion)
			v[winValueReleaseID] = winDenied(winRegSZ)
		}, with(func(o *OSInfo) { o.Version = "" }), []string{AttrOSVersion}, nil},
		{"CurrentBuild absent uses CurrentBuildNumber", func(v map[string]winRegValue) { delete(v, winValueCurrentBuild) },
			std, nil, []string{AttrOSBuild}},
		{"denied CurrentBuild does not fall back and leaves the name ambiguous", func(v map[string]winRegValue) { v[winValueCurrentBuild] = winDenied(winRegSZ) },
			with(func(o *OSInfo) { o.Build, o.Name = "", "" }), []string{AttrOSBuild, AttrOSName}, nil},
		{"CurrentBuild is not a number", func(v map[string]winRegValue) { v[winValueCurrentBuild] = winSZ("19045a") },
			with(func(o *OSInfo) { o.Build, o.Name = "", "" }), []string{AttrOSBuild, AttrOSName}, nil},
		{"UBR absent keeps the bare build", func(v map[string]winRegValue) { delete(v, winValueUBR) },
			with(func(o *OSInfo) { o.Build = "19045" }), nil, nil},
		{"UBR as REG_QWORD", func(v map[string]winRegValue) { v[winValueUBR] = winRegValue{Type: winRegQWORD, Num: 4894} },
			std, nil, nil},
		{"UBR of the wrong type fails the build, not the name", func(v map[string]winRegValue) { v[winValueUBR] = winSZ("4894") },
			with(func(o *OSInfo) { o.Build = "" }), []string{AttrOSBuild}, nil},
		{"denied UBR fails the build", func(v map[string]winRegValue) { v[winValueUBR] = winDenied(winRegDWORD) },
			with(func(o *OSInfo) { o.Build = "" }), []string{AttrOSBuild}, nil},
		{"ProductName absent is missing, not failed", func(v map[string]winRegValue) { delete(v, winValueProductName) },
			with(func(o *OSInfo) { o.Name = "" }), nil, nil},
		{"ProductName as REG_EXPAND_SZ", func(v map[string]winRegValue) {
			v[winValueProductName] = winRegValue{Type: winRegExpandSZ, Str: "Windows 10 Enterprise"}
		}, std, nil, nil},
		{"ProductName of the wrong type", func(v map[string]winRegValue) { v[winValueProductName] = winRegValue{Type: winRegBinary} },
			with(func(o *OSInfo) { o.Name = "" }), []string{AttrOSName}, nil},
		{"surrounding blanks are trimmed", func(v map[string]winRegValue) { v[winValueProductName] = winSZ("  Windows 10 Enterprise ") },
			std, nil, nil},
		{"control character", func(v map[string]winRegValue) { v[winValueProductName] = winSZ("Windows 10\x1bEnterprise") },
			with(func(o *OSInfo) { o.Name = "" }), []string{AttrOSName}, nil},
		{"invalid text", func(v map[string]winRegValue) { v[winValueProductName] = winSZ("Windows 10 \uFFFD") },
			with(func(o *OSInfo) { o.Name = "" }), []string{AttrOSName}, nil},
		{"overlong value", func(v map[string]winRegValue) { v[winValueProductName] = winSZ(strings.Repeat("W", winMaxValueLen+1)) },
			with(func(o *OSInfo) { o.Name = "" }), []string{AttrOSName}, nil},
	}
	for _, c := range cases {
		v := winClient()
		c.mutate(v)
		got, err := windowsVersionFromValues(v)
		if got.Info != c.want {
			t.Fatalf("%s: got %+v, want %+v (err %v)", c.name, got.Info, c.want, err)
		}
		failed := winFailedFields(err)
		sort.Strings(failed)
		want := append([]string(nil), c.failed...)
		sort.Strings(want)
		if !reflect.DeepEqual(failed, want) {
			t.Fatalf("%s: failed fields %v, want %v (err %v)", c.name, failed, want, err)
		}
		if (err != nil) != (len(c.failed) > 0) {
			t.Fatalf("%s: err %v", c.name, err)
		}
		if d := winDerivedFields(got); !reflect.DeepEqual(d, c.derived) {
			t.Fatalf("%s: derived %v, want %v", c.name, d, c.derived)
		}
		for name, raw := range v {
			if _, kept := got.Values[name]; kept != (raw.Err == nil && (raw.Type == winRegSZ || raw.Type == winRegExpandSZ || raw.Type == winRegDWORD || raw.Type == winRegQWORD)) {
				t.Fatalf("%s: raw value %s kept=%v: %+v", c.name, name, kept, raw)
			}
		}
	}
}

// TestWinVersionNoFields: a key without any mapped value is ErrNoFields, as
// for the other parsers.
func TestWinVersionNoFields(t *testing.T) {
	for _, v := range []map[string]winRegValue{nil, {"SystemRoot": winSZ(`C:\Windows`)}, {winValueEditionID: winSZ("Professional")}} {
		if _, err := windowsVersionFromValues(v); !errors.Is(err, ErrNoFields) {
			t.Fatalf("%v: %v, want ErrNoFields", v, err)
		}
	}
}

// TestWinVersionErrorClassification: Win32 codes map to the fs sentinels the
// probe classifies on every host (missing key: unavailable; access denied:
// permission_denied), and a field error keeps its class through the
// aggregate error.
func TestWinVersionErrorClassification(t *testing.T) {
	cause := errors.New("cause")
	for _, c := range []struct {
		code       uint32
		notExist   bool
		permission bool
	}{
		{winErrorFileNotFound, true, false},
		{winErrorPathNotFound, true, false},
		{winErrorAccessDenied, false, true},
		{0, false, false},
		{1234, false, false},
	} {
		err := newWinRegError("open key", c.code, cause)
		if errors.Is(err, fs.ErrNotExist) != c.notExist || errors.Is(err, fs.ErrPermission) != c.permission {
			t.Fatalf("code %d: notExist %v permission %v", c.code, errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission))
		}
		if !errors.Is(err, cause) || err.Error() != "registry open key: cause" {
			t.Fatalf("code %d: %q does not wrap its cause", c.code, err.Error())
		}
	}
	if got := newWinRegError("read x", 5, nil).Error(); got != "registry read x: unknown error" {
		t.Fatalf("nil cause: %q", got)
	}

	v := winClient()
	v[winValueUBR] = winDenied(winRegDWORD)
	v[winValueDisplayVersion] = winDWORD(1)
	_, err := windowsVersionFromValues(v)
	var ve *winVersionError
	if !errors.As(err, &ve) || !errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("aggregate error lost its class: %v", err)
	}
	if !errors.Is(ve.Field(AttrOSBuild), fs.ErrPermission) || errors.Is(ve.Field(AttrOSVersion), fs.ErrPermission) || ve.Field(AttrOSName) != nil {
		t.Fatalf("per-field errors: %v", err)
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "os_build: ") || !strings.Contains(msg, "; os_version: DisplayVersion has type REG_DWORD, want REG_SZ") {
		t.Fatalf("message %q", msg)
	}
}

// TestWinVersionProbeStates: through common.identity, a missing key is
// unavailable, a denied key or value is permission_denied, a value of the
// wrong type is partial with a failed field, and a missing value is partial
// with a missing field (SPEC-0471 TF06-R2). The fixture path ends in the
// same captured artifact the registry reader would give.
func TestWinVersionProbeStates(t *testing.T) {
	collect := func(r WindowsVersionReader) trustfreeze.ProbeResult {
		cc, _ := collectCtx("windows", probe.FakeFiles{}, probe.NewFakeRunner())
		return (&IdentityProbe{Windows: r}).Collect(context.Background(), cc)
	}
	osFieldsOf := func(t *testing.T, r trustfreeze.ProbeResult) map[string]string {
		t.Helper()
		return artifact(t, r, ArtifactOS).Attributes
	}

	r := collect(winValuesReader{values: winRegQuery(t, winFixtureBytes(t, "win11-23h2-pro.txt"))})
	if r.Status != trustfreeze.StatusCaptured || r.Error != nil {
		t.Fatalf("fixture: %s %+v", r.Status, r.Warnings)
	}
	wantAttrs(t, artifact(t, r, ArtifactOS), map[string]string{
		AttrOSFamily: "windows", AttrArch: "arm64", AttrOSName: "Windows 11 Pro", AttrOSVersion: "23H2", AttrOSBuild: "22631.4169",
	})
	// The Windows 11 name is derived from the build number, and says so.
	if !warning(r, probe.DiagFieldNotApplicable, AttrKernelRelease) || !warning(r, DiagValueDerived, AttrOSName) || len(r.Warnings) != 2 {
		t.Fatalf("warnings %+v", r.Warnings)
	}

	r = collect(winValuesReader{openErr: newWinRegError("open "+WindowsCurrentVersionKey, winErrorAccessDenied, errors.New("Access is denied."))})
	if r.Status != trustfreeze.StatusPermissionDenied || r.Error == nil || r.Error.Class != probe.ClassPermissionDenied {
		t.Fatalf("denied key: %s %+v", r.Status, r.Error)
	}
	for _, f := range []string{AttrOSName, AttrOSVersion, AttrOSBuild} {
		if !warning(r, probe.DiagFieldPermissionDenied, f) {
			t.Fatalf("denied key: no permission diagnostic for %s: %+v", f, r.Warnings)
		}
	}
	if !hasArtifact(r, ArtifactHost) {
		t.Fatal("denied key: host artifact lost")
	}

	r = collect(winValuesReader{openErr: newWinRegError("open "+WindowsCurrentVersionKey, winErrorFileNotFound, errors.New("The system cannot find the file specified."))})
	if r.Status != trustfreeze.StatusUnavailable || !warning(r, probe.DiagFieldUnavailable, AttrOSName) {
		t.Fatalf("missing key: %s %+v", r.Status, r.Warnings)
	}

	v := winClient()
	v[winValueUBR] = winDenied(winRegDWORD)
	r = collect(winValuesReader{values: v})
	if r.Status != trustfreeze.StatusPermissionDenied || !warning(r, probe.DiagFieldPermissionDenied, AttrOSBuild) {
		t.Fatalf("denied UBR: %s %+v", r.Status, r.Warnings)
	}
	if a := osFieldsOf(t, r); a[AttrOSName] != "Windows 10 Enterprise" || a[AttrOSVersion] != "22H2" || a[AttrOSBuild] != "" {
		t.Fatalf("denied UBR attributes %v", a)
	}

	v = winClient()
	v[winValueProductName] = winRegValue{Type: winRegBinary}
	r = collect(winValuesReader{values: v})
	if r.Status != trustfreeze.StatusPartial || !warning(r, probe.DiagFieldFailed, AttrOSName) {
		t.Fatalf("binary ProductName: %s %+v", r.Status, r.Warnings)
	}

	v = winClient()
	delete(v, winValueDisplayVersion)
	delete(v, winValueReleaseID)
	r = collect(winValuesReader{values: v})
	if r.Status != trustfreeze.StatusPartial || !warning(r, trustfreeze.DiagFieldMissing, AttrOSVersion) {
		t.Fatalf("no version: %s %+v", r.Status, r.Warnings)
	}
}

// TestWinVersionReaderContract pins the key and the value names the reader
// reads, so the reader and the mapping cannot drift apart.
func TestWinVersionReaderContract(t *testing.T) {
	if `HKLM\`+winCurrentVersionSubkey != WindowsCurrentVersionKey {
		t.Fatalf("subkey %q does not match %q", winCurrentVersionSubkey, WindowsCurrentVersionKey)
	}
	if !sort.StringsAreSorted(winStringValueNames) {
		t.Fatalf("value names not sorted: %v", winStringValueNames)
	}
	want := []string{winValueCurrentBuild, winValueCurrentBuildNumber, winValueDisplayVersion, winValueEditionID, winValueInstallationType, winValueProductName, winValueReleaseID}
	if !reflect.DeepEqual(winStringValueNames, want) {
		t.Fatalf("value names %v, want %v", winStringValueNames, want)
	}
	if winRegTypeName(winRegDWORD) != "REG_DWORD" || winRegTypeName(99) != "registry type 99" {
		t.Fatal("type names")
	}
}

// TestWinVersionFixtureOrigins: every file in testdata/windows is in the
// fixture table with an honest origin, and no fixture carries values that
// identify a machine, an owner or a license (public plane rule).
func TestWinVersionFixtureOrigins(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "windows"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, f := range winFixtures {
		listed[f.file] = true
		if f.origin != "reconstructed" && f.origin != "synthetic" && !strings.HasPrefix(f.origin, "captured") {
			t.Errorf("%s: origin %q", f.file, f.origin)
		}
	}
	personal := []string{"RegisteredOwner", "RegisteredOrganization", "ProductId", "DigitalProductId", "DigitalProductId4", "InstallDate", "InstallTime", "BuildGUID"}
	for _, e := range entries {
		if !listed[e.Name()] {
			t.Errorf("testdata/windows/%s is not in the fixture table", e.Name())
			continue
		}
		values := winRegQuery(t, winFixtureBytes(t, e.Name()))
		for _, p := range personal {
			if _, ok := values[p]; ok {
				t.Errorf("%s holds %s", e.Name(), p)
			}
		}
	}
}

// TestWinVersionRealRegistry reads the real CurrentVersion key, read-only,
// when the test runs on Windows (the windows-latest CI job). Everywhere else
// the default reader must say not applicable.
func TestWinVersionRealRegistry(t *testing.T) {
	r := DefaultWindowsVersionReader()
	if runtime.GOOS != "windows" {
		if _, err := r.Read(); !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("non-windows default reader: %v", err)
		}
		return
	}
	info, err := r.Read()
	if err != nil {
		t.Fatalf("registry read: %v", err)
	}
	if info.Name == "" || info.Version == "" || !regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`).MatchString(info.Build) {
		t.Fatalf("implausible identity %+v", info)
	}
	build, _ := strconv.Atoi(strings.SplitN(info.Build, ".", 2)[0])
	if winNamesWindows10(info.Name) && build >= windows11FirstBuild {
		t.Fatalf("%q on build %d: the Windows 11 rule did not apply", info.Name, build)
	}
	detail, ok := r.(interface {
		readDetail() (windowsVersion, error)
	})
	if !ok {
		t.Fatal("the registry reader does not expose its raw values")
	}
	d, err := detail.readDetail()
	if err != nil || d.Values[winValueProductName] == "" || d.Values[winValueCurrentBuild] == "" {
		t.Fatalf("raw values %v: %v", d.Values, err)
	}

	cc, _ := collectCtx("windows", probe.FakeFiles{}, probe.NewFakeRunner())
	cc.GOARCH = runtime.GOARCH
	res := (&IdentityProbe{Windows: r}).Collect(context.Background(), cc)
	if res.Status != trustfreeze.StatusCaptured || len(res.Warnings) != 1 {
		t.Fatalf("status %s %q %+v", res.Status, res.Reason, res.Warnings)
	}
}
