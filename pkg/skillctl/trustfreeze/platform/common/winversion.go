package common

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file maps the values of the Windows CurrentVersion registry key
// (WindowsCurrentVersionKey) to OSInfo. The mapping is a pure function, so
// every rule below runs against fixtures on any host (testdata/windows);
// winversion_windows.go only reads the values.
//
// Mapping:
//
//	OSInfo.Name     ProductName ("Windows Server 2022 Datacenter"), except
//	                that a client whose ProductName starts with "Windows 10"
//	                and whose build is windows11FirstBuild or later is named
//	                "Windows 11 <edition>" (see below)
//	OSInfo.Version  DisplayVersion ("23H2"); ReleaseId ("1809") only when
//	                DisplayVersion does not exist (builds before 20H2)
//	OSInfo.Build    CurrentBuild ("22631"), CurrentBuildNumber only when
//	                CurrentBuild does not exist, then "." and UBR when UBR
//	                exists ("22631.4169", the build winver shows)
//	OSInfo.KernelRelease  never set; Windows has no uname
//
// Windows 11 still reports ProductName "Windows 10 <edition>" in this key for
// compatibility. Microsoft identifies Windows 11 by build: 22000 (21H2) is
// the first Windows 11 build, every Windows 10 build is below it. The name
// is therefore derived from the build for clients, and the derivation is
// recorded (windowsVersion.Derived). Servers keep their ProductName: Windows
// Server 2025 has build 26100 and must not be called Windows 11, so
// InstallationType ("Server", "Server Core", "Nano Server") or an EditionID
// starting with "Server" stops the rule. Without a readable build number a
// "Windows 10" ProductName is ambiguous and os_name fails instead of
// guessing.
//
// BuildLab and BuildLabEx are not used: on Windows 11 23H2 (an enablement
// package over 22H2) they still name build 22621 while CurrentBuild is 22631.
//
// A fallback is used only when the preferred value does not exist or is
// empty. A value that exists but cannot be read, has an unexpected registry
// type or is not plausible text makes its field fail; it never falls back to
// an older or less exact value. UBR is part of os_build: if UBR exists but
// cannot be read, os_build fails rather than reporting the bare build. An
// absent value leaves its field empty: nothing is invented.

// Values read from the CurrentVersion key.
const (
	winValueCurrentBuild       = "CurrentBuild"
	winValueCurrentBuildNumber = "CurrentBuildNumber"
	winValueDisplayVersion     = "DisplayVersion"
	winValueEditionID          = "EditionID"
	winValueInstallationType   = "InstallationType"
	winValueProductName        = "ProductName"
	winValueReleaseID          = "ReleaseId"
	winValueUBR                = "UBR"
)

// winCurrentVersionSubkey is WindowsCurrentVersionKey below HKEY_LOCAL_MACHINE.
const winCurrentVersionSubkey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// winStringValueNames are the REG_SZ values the reader reads, sorted. UBR, a
// REG_DWORD, is read separately.
var winStringValueNames = []string{
	winValueCurrentBuild,
	winValueCurrentBuildNumber,
	winValueDisplayVersion,
	winValueEditionID,
	winValueInstallationType,
	winValueProductName,
	winValueReleaseID,
}

// windows11FirstBuild is the first Windows 11 build (version 21H2).
const windows11FirstBuild = 22000

// winMaxValueLen bounds a value. Real values are a few bytes ("22631",
// "Windows 10 Enterprise LTSC 2019").
const winMaxValueLen = 256

// Win32 registry value types (winnt.h).
const (
	winRegNone           uint32 = 0
	winRegSZ             uint32 = 1
	winRegExpandSZ       uint32 = 2
	winRegBinary         uint32 = 3
	winRegDWORD          uint32 = 4
	winRegDWORDBigEndian uint32 = 5
	winRegLink           uint32 = 6
	winRegMultiSZ        uint32 = 7
	winRegQWORD          uint32 = 11
)

var winRegTypeNames = map[uint32]string{
	winRegNone:           "REG_NONE",
	winRegSZ:             "REG_SZ",
	winRegExpandSZ:       "REG_EXPAND_SZ",
	winRegBinary:         "REG_BINARY",
	winRegDWORD:          "REG_DWORD",
	winRegDWORDBigEndian: "REG_DWORD_BIG_ENDIAN",
	winRegLink:           "REG_LINK",
	winRegMultiSZ:        "REG_MULTI_SZ",
	winRegQWORD:          "REG_QWORD",
}

func winRegTypeName(t uint32) string {
	if n, ok := winRegTypeNames[t]; ok {
		return n
	}
	return "registry type " + strconv.FormatUint(uint64(t), 10)
}

// winRegValue is one value of the CurrentVersion key as the reader saw it. A
// value that does not exist is absent from the map, not a winRegValue.
type winRegValue struct {
	// Type is the Win32 registry type of the value.
	Type uint32
	// Str is the data of a REG_SZ or REG_EXPAND_SZ value (not expanded).
	Str string
	// Num is the data of a REG_DWORD or REG_QWORD value.
	Num uint64
	// Err is set when the value exists but could not be read.
	Err error
}

// text renders a string or integer value for evidence.
func (v winRegValue) text() (string, bool) {
	switch v.Type {
	case winRegSZ, winRegExpandSZ:
		return v.Str, true
	case winRegDWORD, winRegQWORD:
		return strconv.FormatUint(v.Num, 10), true
	}
	return "", false
}

// Win32 error codes the registry errors are classified by (winerror.h).
const (
	winErrorFileNotFound = 2
	winErrorPathNotFound = 3
	winErrorAccessDenied = 5
)

// winRegError is a registry failure with its Win32 error code. It matches
// fs.ErrNotExist for a key that does not exist and fs.ErrPermission for
// access denied, on every OS, so the probe reports unavailable and
// permission_denied (fileErrorState) and this is tested on any host.
type winRegError struct {
	op   string
	code uint32
	err  error
}

// newWinRegError wraps err of op; code is its Win32 error code, 0 if none.
func newWinRegError(op string, code uint32, err error) *winRegError {
	if err == nil {
		err = errors.New("unknown error")
	}
	return &winRegError{op: op, code: code, err: err}
}

func (e *winRegError) Error() string { return "registry " + e.op + ": " + e.err.Error() }

// Unwrap returns the underlying error.
func (e *winRegError) Unwrap() error { return e.err }

// Is classifies the Win32 error code.
func (e *winRegError) Is(target error) bool {
	switch target {
	case fs.ErrNotExist:
		return e.code == winErrorFileNotFound || e.code == winErrorPathNotFound
	case fs.ErrPermission:
		return e.code == winErrorAccessDenied
	}
	return false
}

// winFieldError is the reason one OSInfo field could not be established.
type winFieldError struct {
	// Field is AttrOSName, AttrOSVersion or AttrOSBuild.
	Field string
	Err   error
}

// winVersionError lists the fields a read could not establish, sorted by
// field. errors.Is sees every field error, so a value that was denied still
// matches fs.ErrPermission.
type winVersionError struct {
	fields []winFieldError
}

func (e *winVersionError) Error() string {
	parts := make([]string, 0, len(e.fields))
	for _, f := range e.fields {
		parts = append(parts, f.Field+": "+f.Err.Error())
	}
	return strings.Join(parts, "; ")
}

// Unwrap returns the field errors.
func (e *winVersionError) Unwrap() []error {
	out := make([]error, 0, len(e.fields))
	for _, f := range e.fields {
		out = append(out, f.Err)
	}
	return out
}

// Field returns the error of one field, or nil.
func (e *winVersionError) Field(name string) error {
	for _, f := range e.fields {
		if f.Field == name {
			return f.Err
		}
	}
	return nil
}

// windowsVersion is the outcome of mapping one value set.
type windowsVersion struct {
	Info OSInfo
	// Values holds every value that exists and was read, as text by value
	// name ("UBR": "4169"): the input of the mapping, for evidence.
	Values map[string]string
	// Derived explains, by attribute name, each field that is not a plain
	// copy of its preferred value.
	Derived map[string]string
}

// windowsVersionFromValues maps a CurrentVersion value set to OSInfo (see the
// mapping at the top of this file). The error is a *winVersionError naming
// each field that could not be established, or ErrNoFields when the set
// yields no field at all. Info holds every field that was established, even
// when the error is not nil.
func windowsVersionFromValues(values map[string]winRegValue) (windowsVersion, error) {
	out := windowsVersion{Values: map[string]string{}, Derived: map[string]string{}}
	for name, v := range values {
		if v.Err != nil {
			continue
		}
		if s, ok := v.text(); ok {
			out.Values[name] = s
		}
	}
	var failed []winFieldError
	fail := func(field string, err error) { failed = append(failed, winFieldError{Field: field, Err: err}) }

	build, buildSource, buildNum, buildErr := winBuild(values)
	switch {
	case buildErr != nil:
		fail(AttrOSBuild, buildErr)
	case build != "":
		ubr, hasUBR, err := winUBR(values)
		if err != nil {
			fail(AttrOSBuild, err)
			break
		}
		out.Info.Build = build
		if hasUBR {
			out.Info.Build += "." + strconv.FormatUint(ubr, 10)
		}
		if buildSource != winValueCurrentBuild {
			out.Derived[AttrOSBuild] = buildSource + " (" + winValueCurrentBuild + " does not exist)"
		}
	}

	switch dv, ok, err := winString(values, winValueDisplayVersion); {
	case err != nil:
		fail(AttrOSVersion, err)
	case ok:
		out.Info.Version = dv
	default:
		switch rid, ok, err := winString(values, winValueReleaseID); {
		case err != nil:
			fail(AttrOSVersion, err)
		case ok:
			out.Info.Version = rid
			out.Derived[AttrOSVersion] = winValueReleaseID + " (" + winValueDisplayVersion + " does not exist)"
		}
	}

	switch pn, ok, err := winString(values, winValueProductName); {
	case err != nil:
		fail(AttrOSName, err)
	case !ok:
	case !winNamesWindows10(pn) || winIsServer(values):
		out.Info.Name = pn
	case buildErr != nil || build == "":
		fail(AttrOSName, fmt.Errorf("%s %q is also what Windows 11 reports; without a readable build number the two cannot be told apart", winValueProductName, pn))
	case buildNum >= windows11FirstBuild:
		out.Info.Name = "Windows 11" + strings.TrimPrefix(pn, "Windows 10")
		out.Derived[AttrOSName] = fmt.Sprintf("%s %q read as Windows 11 because %s %s is at least %d", winValueProductName, pn, buildSource, build, windows11FirstBuild)
	default:
		out.Info.Name = pn
	}

	if len(failed) > 0 {
		sort.Slice(failed, func(i, j int) bool { return failed[i].Field < failed[j].Field })
		return out, &winVersionError{fields: failed}
	}
	if out.Info == (OSInfo{}) {
		return out, ErrNoFields
	}
	return out, nil
}

// winString returns the trimmed text of a string value. ok is false when the
// value does not exist or is empty; err is set when it exists but is not a
// readable, plausible string.
func winString(values map[string]winRegValue, name string) (string, bool, error) {
	v, exists := values[name]
	switch {
	case !exists:
		return "", false, nil
	case v.Err != nil:
		return "", false, v.Err
	case v.Type != winRegSZ && v.Type != winRegExpandSZ:
		return "", false, fmt.Errorf("%s has type %s, want REG_SZ", name, winRegTypeName(v.Type))
	}
	s := strings.TrimSpace(v.Str)
	if err := checkWinText(s); err != nil {
		return "", false, fmt.Errorf("%s: %w", name, err)
	}
	return s, s != "", nil
}

// winBuild returns the build ("22631"), the value it came from and its
// number. An empty build with a nil error means neither value exists.
func winBuild(values map[string]winRegValue) (string, string, uint64, error) {
	source := winValueCurrentBuild
	s, ok, err := winString(values, source)
	if err == nil && !ok {
		source = winValueCurrentBuildNumber
		s, ok, err = winString(values, source)
	}
	if err != nil || !ok {
		return "", source, 0, err
	}
	n, perr := strconv.ParseUint(s, 10, 32)
	if perr != nil {
		return "", source, 0, fmt.Errorf("%s %q is not a build number", source, s)
	}
	return s, source, n, nil
}

// winUBR returns the update build revision. ok is false when UBR does not
// exist.
func winUBR(values map[string]winRegValue) (uint64, bool, error) {
	v, exists := values[winValueUBR]
	switch {
	case !exists:
		return 0, false, nil
	case v.Err != nil:
		return 0, false, v.Err
	case v.Type != winRegDWORD && v.Type != winRegQWORD:
		return 0, false, fmt.Errorf("%s has type %s, want REG_DWORD", winValueUBR, winRegTypeName(v.Type))
	}
	return v.Num, true, nil
}

// winNamesWindows10 reports a ProductName of the "Windows 10" family, which
// Windows 11 clients also report.
func winNamesWindows10(productName string) bool {
	return productName == "Windows 10" || strings.HasPrefix(productName, "Windows 10 ")
}

// winIsServer reports a server installation. It only guards the Windows 11
// rule, so a guard value that cannot be read counts as absent.
func winIsServer(values map[string]winRegValue) bool {
	if it, ok, err := winString(values, winValueInstallationType); err == nil && ok && strings.Contains(strings.ToLower(it), "server") {
		return true
	}
	ed, ok, err := winString(values, winValueEditionID)
	return err == nil && ok && strings.HasPrefix(strings.ToLower(ed), "server")
}

// checkWinText rejects text no CurrentVersion value holds: control
// characters, text that was not valid UTF-16 and overlong values.
func checkWinText(s string) error {
	if len(s) > winMaxValueLen {
		return fmt.Errorf("value longer than %d bytes", winMaxValueLen)
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return errors.New("value contains a control character or invalid text")
		}
	}
	return nil
}

// Native machine types of IsWow64Process2 (winnt.h IMAGE_FILE_MACHINE_*).
const (
	winMachineI386  uint16 = 0x014c
	winMachineARMNT uint16 = 0x01c4
	winMachineAMD64 uint16 = 0x8664
	winMachineARM64 uint16 = 0xaa64
)

// winMachineArch spells a native machine type the way GOARCH does. An
// unknown type is an error, never a guess.
func winMachineArch(m uint16) (string, error) {
	switch m {
	case winMachineAMD64:
		return "amd64", nil
	case winMachineARM64:
		return "arm64", nil
	case winMachineI386:
		return "386", nil
	case winMachineARMNT:
		return "arm", nil
	}
	return "", fmt.Errorf("unknown native machine type 0x%04x", m)
}
