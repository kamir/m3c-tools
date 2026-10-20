//go:build windows

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWritePrivateFileProtectsWindowsDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	permissive, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := permissive.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(path, []byte("synthetic secret")); err != nil {
		t.Fatal(err)
	}
	assertPrivateWindowsDACL(t, path)
}

func TestCreatePrivateTempProtectsWindowsDACLBeforeWrite(t *testing.T) {
	directory := t.TempDir()
	// Every new ordinary child would inherit Everyone's full access here.
	parent, err := windows.SecurityDescriptorFromString("D:P(A;OICI;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := parent.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	file, err := createPrivateTemp(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatal("temporary file must still be empty when its permissions are checked")
	}
	assertPrivateWindowsDACL(t, file.Name())
}

func assertPrivateWindowsDACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("private file DACL still inherits permissions")
	}
	// The query-only pseudo token is OS-owned and must not be closed.
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(user.User.Sid) {
		t.Fatal("private file owner is not the current user")
	}
	permissions, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if permissions == nil || permissions.AceCount != 2 {
		t.Fatalf("expected exactly owner and SYSTEM permissions: %s", descriptor.String())
	}
	entries := regexp.MustCompile(`\(([^)]+)\)`).FindAllStringSubmatch(descriptor.String(), -1)
	sawUser, sawSystem := false, false
	for _, entry := range entries {
		fields := strings.Split(entry[1], ";")
		if len(fields) != 6 || fields[0] != "A" || strings.Contains(fields[1], "ID") {
			t.Fatalf("unexpected ACE: %s", entry[0])
		}
		if fields[2] != "GA" && fields[2] != "FA" {
			t.Fatalf("missing full control: %s", entry[0])
		}
		trustee, err := windows.StringToSid(fields[5])
		if err != nil {
			t.Fatalf("invalid trustee %s: %v", fields[5], err)
		}
		system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		if err != nil {
			t.Fatal(err)
		}
		isUser, isSystem := trustee.Equals(user.User.Sid), trustee.Equals(system)
		if !isUser && !isSystem {
			t.Fatalf("unexpected trustee: %s", entry[0])
		}
		sawUser = sawUser || isUser
		sawSystem = sawSystem || isSystem
	}
	if !sawUser || !sawSystem {
		t.Fatalf("missing owner or SYSTEM trustee: %s", descriptor.String())
	}
}
