//go:build windows

package artifactauth

// The round trip against the real DPAPI, which is the only thing that proves the
// Windows write side works. It is the counterpart of store_darwin_test.go, and
// until now it did not exist: the whole DPAPI store, StoreCred and DeleteCred
// included, shipped with no test at all while the macOS twin had one.
//
// Everything here redirects %LOCALAPPDATA% to a temp dir and uses a service name
// no backend maps to, so a run cannot read, overwrite or delete an operator's
// real credential.
//
// These tests do NOT skip when DPAPI fails. CryptProtectData is available to any
// interactive user account with a loaded profile, which is what the
// windows-latest runner gives us, so a failure here is a defect and not an
// environment quirk. A skip would put the write side back where it was: shipped
// and unproven.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	selftestService = "m3c-skillctl-selftest"
	selftestAccount = "roundtrip.invalid"
)

// isolateCredDir points %LOCALAPPDATA% at a temp dir for the duration of one
// test, so nothing this file writes lands in the real user profile. It returns
// the temp %LOCALAPPDATA% root, not the credential dir underneath it.
func isolateCredDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("LOCALAPPDATA", dir)
	return dir
}

func TestDPAPIRoundTrip(t *testing.T) {
	isolateCredDir(t)

	// Quotes, a backslash, an inner space and a non-ASCII rune: DPAPI carries
	// opaque bytes, and the test says so rather than assuming it.
	const secret = `glpat-round trip "quoted" \backslash ümlaut`

	if err := StoreCred(selftestService, selftestAccount, secret); err != nil {
		t.Fatalf("StoreCred: %v", err)
	}
	t.Cleanup(func() { _ = DeleteCred(selftestService, selftestAccount) })

	if got := osCredStore(selftestService, selftestAccount); got != secret {
		t.Fatalf("read back %q, want %q", got, secret)
	}

	// Overwriting must update in place, because a token rotation re-runs the same
	// command and a half-written or stale credential at that moment would be the
	// worst timing.
	const rotated = "glpat-rotated"
	if err := StoreCred(selftestService, selftestAccount, rotated); err != nil {
		t.Fatalf("second store (rotation): %v", err)
	}
	if got := osCredStore(selftestService, selftestAccount); got != rotated {
		t.Fatalf("after rotation read back %q, want %q", got, rotated)
	}

	if err := DeleteCred(selftestService, selftestAccount); err != nil {
		t.Fatalf("DeleteCred: %v", err)
	}
	if got := osCredStore(selftestService, selftestAccount); got != "" {
		t.Fatalf("after delete the credential is still readable: %q", got)
	}
	// Deleting what is already gone is not an error: the caller asked for it to be
	// absent, and it is.
	if err := DeleteCred(selftestService, selftestAccount); err != nil {
		t.Errorf("second delete: %v", err)
	}
}

// The blob on disk must not contain the token. This is the entire claim the
// Windows store makes over a plaintext file, so it is worth an assertion rather
// than a comment: a world-readable copy of the file is useless to another user.
func TestDPAPIBlobOnDiskIsNotThePlaintext(t *testing.T) {
	isolateCredDir(t)

	const secret = "glpat-must-not-appear-on-disk"
	if err := StoreCred(selftestService, selftestAccount, secret); err != nil {
		t.Fatalf("StoreCred: %v", err)
	}
	t.Cleanup(func() { _ = DeleteCred(selftestService, selftestAccount) })

	p, err := credPath(selftestService, selftestAccount)
	if err != nil {
		t.Fatalf("credPath: %v", err)
	}
	enc, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("reading the stored blob: %v", err)
	}
	if len(enc) == 0 {
		t.Fatal("the stored blob is empty; nothing was protected")
	}
	if bytes.Contains(enc, []byte(secret)) {
		t.Error("the token appears verbatim in the stored file; it was not DPAPI-protected")
	}
	// UTF-16 is the other way a Windows secret leaks into a file, so rule it out too.
	var wide []byte
	for _, b := range []byte(secret) {
		wide = append(wide, b, 0)
	}
	if bytes.Contains(enc, wide) {
		t.Error("the token appears UTF-16-encoded in the stored file")
	}
}

// A corrupted or foreign blob must read as "no credential", not as a panic and
// not as garbage handed to a registry as a bearer token. This is the fail-soft
// contract osCredStore shares with the macOS keychain reader.
func TestDPAPIUndecryptableBlobReadsAsAbsent(t *testing.T) {
	isolateCredDir(t)

	p, err := credPath(selftestService, "corrupt.invalid")
	if err != nil {
		t.Fatalf("credPath: %v", err)
	}
	if err := os.WriteFile(p, []byte("this is not a DPAPI blob"), 0o600); err != nil {
		t.Fatalf("writing the corrupt blob: %v", err)
	}
	if got := osCredStore(selftestService, "corrupt.invalid"); got != "" {
		t.Errorf("an undecryptable blob returned %q, want the empty (anonymous) result", got)
	}
}

// An empty account is refused by both sides. The account is the registry host,
// and it is the only thing separating one instance's token from another's: a
// write or a delete against "" would act on a shared, unnamed item.
func TestDPAPIRefusesAnEmptyAccount(t *testing.T) {
	isolateCredDir(t)

	if err := StoreCred(selftestService, "", "s"); err == nil ||
		!strings.Contains(err.Error(), "non-empty account") {
		t.Errorf("StoreCred with an empty account = %v, want a refusal naming the account", err)
	}
	if err := DeleteCred(selftestService, ""); err == nil ||
		!strings.Contains(err.Error(), "non-empty account") {
		t.Errorf("DeleteCred with an empty account = %v, want a refusal naming the account", err)
	}
	// The read side answers "" rather than erroring, because it is on the resolver's
	// fail-soft-to-anonymous path.
	if got := osCredStore(selftestService, ""); got != "" {
		t.Errorf("osCredStore with an empty account = %q, want %q", got, "")
	}
}

// With %LOCALAPPDATA% unset, credDir falls back under the user profile. The test
// runs a whole round trip through the fallback rather than only comparing paths,
// because the failure mode that matters is a store that silently writes nowhere
// on a machine where the variable is missing (a service account, a stripped
// environment, some CI images).
func TestCredDirFallsBackWhenLOCALAPPDATAIsUnset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LOCALAPPDATA", "")
	t.Setenv("USERPROFILE", home)

	dir, err := credDir()
	if err != nil {
		t.Fatalf("credDir with LOCALAPPDATA unset: %v", err)
	}
	want := filepath.Join(home, "AppData", "Local", "m3c", "artifactauth")
	if dir != want {
		t.Fatalf("credDir = %q, want %q", dir, want)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("credDir did not create the directory: %v", err)
	}

	const secret = "glpat-fallback-path"
	if err := StoreCred(selftestService, selftestAccount, secret); err != nil {
		t.Fatalf("StoreCred through the fallback: %v", err)
	}
	t.Cleanup(func() { _ = DeleteCred(selftestService, selftestAccount) })
	if got := osCredStore(selftestService, selftestAccount); got != secret {
		t.Fatalf("fallback read back %q, want %q", got, secret)
	}

	// It really landed under the profile, not in some ambient location.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one credential file under %q, got %v (err %v)", dir, entries, err)
	}
}

// A host carrying a port must stay one path component. On Windows a ':' in a
// filename does not fail: it opens an NTFS alternate data stream, so the write
// would appear to succeed and the read would find nothing. safeCredName is what
// prevents that, and this pins it end to end.
func TestHostWithAPortStaysOneFilenameComponent(t *testing.T) {
	root := isolateCredDir(t)

	const host = "192.168.0.135:8929"
	const secret = "glpat-host-with-port"
	if err := StoreCred(selftestService, host, secret); err != nil {
		t.Fatalf("StoreCred: %v", err)
	}
	t.Cleanup(func() { _ = DeleteCred(selftestService, host) })

	p, err := credPath(selftestService, host)
	if err != nil {
		t.Fatalf("credPath: %v", err)
	}
	base := filepath.Base(p)
	if strings.ContainsAny(base, `:\/`) {
		t.Errorf("credential filename %q still contains a path or stream separator", base)
	}
	credDirPath := filepath.Join(root, "m3c", "artifactauth")
	if filepath.Dir(p) != credDirPath {
		t.Errorf("credPath escaped the credential dir: %q, want it under %q", p, credDirPath)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("no file at the expected path %q: %v", p, err)
	}
	if got := osCredStore(selftestService, host); got != secret {
		t.Errorf("read back %q, want %q", got, secret)
	}

	// Exactly one file: a ':' swallowed into an alternate data stream would leave
	// the directory looking right while the credential is unreadable, so count.
	entries, err := os.ReadDir(credDirPath)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one file under %q, got %v (err %v)", credDirPath, entries, err)
	}
}

// The public Store / Provisioned / Delete path on Windows, which is what the
// `skillctl token` verb actually calls. It covers store_windows.go's dispatch as
// well, and it pins the thing an operator relies on: after storing, the source
// reported is the protected store and not the environment.
func TestPublicStorePathUsesTheProtectedStore(t *testing.T) {
	isolateCredDir(t)
	// Neutralise an ambient export, which would otherwise win the resolver order
	// and make this test pass without the store being touched at all.
	t.Setenv("M3C_GITLAB_TOKEN", "")

	if !HasProtectedStore() {
		t.Fatal("Windows must report a protected store")
	}
	const host = "git.example.invalid"
	const secret = "glpat-public-api"

	if err := Store("gitlab", TierWrite, host, secret); err != nil {
		t.Fatalf("Store: %v", err)
	}
	t.Cleanup(func() { _ = Delete("gitlab", TierWrite, host) })

	if got := Provisioned("gitlab", TierWrite, host); got != "protected store m3c-skillctl-gitlab" {
		t.Errorf("Provisioned = %q, want the protected store", got)
	}
	if got := osCredStore("m3c-skillctl-gitlab", host); got != secret {
		t.Errorf("the stored token reads back as %q, want %q", got, secret)
	}

	if err := Delete("gitlab", TierWrite, host); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := Provisioned("gitlab", TierWrite, host); got != "" {
		t.Errorf("after Delete, Provisioned = %q, want %q", got, "")
	}
}
