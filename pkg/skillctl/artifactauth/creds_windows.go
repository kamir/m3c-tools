//go:build windows

package artifactauth

// Windows credential store for the write-capable backend PATs (WIN-T6).
//
// The macOS path reads the token from the Keychain (creds.go:keychain). Windows
// has no Keychain, so without this a Windows user's only option is the plaintext
// env var (M3C_GITHUB_TOKEN / M3C_GITLAB_TOKEN): a WRITE-scoped registry token
// sitting in the process environment, inherited by every child process and dumped
// into crash reports. Instead we persist it as a DPAPI-protected blob: the
// ciphertext is bound to the current user account (CryptProtectData), so even a
// world-readable copy of the file is useless to another user or on another machine.
//
// StoreCred writes it once; osCredStore is the read side the Resolver consults
// after the env override and (on macOS only) the Keychain.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// osCredStore returns the token stored for (service, account) via StoreCred, or ""
// if none is stored / it cannot be decrypted (fail-soft to anonymous, exactly like
// the macOS keychain reader). account is the registry host, mirroring keychain().
func osCredStore(service, account string) string {
	if account == "" {
		return ""
	}
	p, err := credPath(service, account)
	if err != nil {
		return ""
	}
	enc, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	plain, err := dpapiUnprotect(enc)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(plain))
}

// StoreCred DPAPI-protects secret and writes it under the per-user credential dir
// for (service, account). This is the write side of the Windows credential store,
// the analogue of `security add-generic-password` on macOS, so an operator can
// keep a write-capable PAT out of the environment. The ciphertext is user-bound by
// DPAPI; the 0600 is best-effort belt-and-braces (Windows ignores the perm bits).
func StoreCred(service, account, secret string) error {
	if account == "" {
		return errors.New("artifactauth: StoreCred needs a non-empty account (registry host)")
	}
	p, err := credPath(service, account)
	if err != nil {
		return err
	}
	enc, err := dpapiProtect([]byte(secret))
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, enc, 0o600); err != nil {
		return err
	}
	return nil
}

// credDir is %LOCALAPPDATA%\m3c\artifactauth (created 0700 if absent).
func credDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, "AppData", "Local")
	}
	dir := filepath.Join(base, "m3c", "artifactauth")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func credPath(service, account string) (string, error) {
	dir, err := credDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, safeCredName(service)+"_"+safeCredName(account)+".dpapi"), nil
}

// safeCredName reduces service/host to a safe single filename component (the host
// may carry ':' for host:port, etc.). Non [A-Za-z0-9._-] becomes '_'.
func safeCredName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// --- DPAPI (CryptProtectData / CryptUnprotectData) via golang.org/x/sys/windows ---

func dpapiProtect(plain []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(plain))}
	if len(plain) > 0 {
		in.Data = &plain[0]
	}
	var out windows.DataBlob
	// CRYPTPROTECT_UI_FORBIDDEN: never pop UI (works headless/in a service).
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer localFree(out.Data)
	return blobBytes(out), nil
}

func dpapiUnprotect(enc []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(enc))}
	if len(enc) > 0 {
		in.Data = &enc[0]
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer localFree(out.Data)
	return blobBytes(out), nil
}

// blobBytes copies a DPAPI output blob into a Go-owned slice before it is freed.
func blobBytes(b windows.DataBlob) []byte {
	if b.Data == nil || b.Size == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(b.Data, b.Size)...)
}

// localFree releases a LocalAlloc'd DPAPI output buffer.
func localFree(p *byte) {
	if p != nil {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(p)))
	}
}
