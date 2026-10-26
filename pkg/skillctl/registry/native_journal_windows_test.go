//go:build windows

package registry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func nativeJournalCheckPlatformPermissions(t *testing.T) {
	t.Helper()
	t.Run("platform-private-permissions", func(t *testing.T) {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Fatal(err)
		}
		for _, directory := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "private-object")
			if directory {
				if err = os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err = os.WriteFile(path, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = nativeJournalSecure(path); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = nativeJournalPermissions(path, info, directory); err != nil {
				sd, queryErr := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
				if queryErr != nil {
					t.Fatal("private descriptor query failed", queryErr)
				}
				// Only the synthetic test object's OS-generated descriptor is logged.
				t.Fatalf("secured native descriptor rejected: user=%s descriptor=%s error=%v", user.User.Sid.String(), sd.String(), err)
			}
			// An actual protected ACL with an extra reader must be refused, even
			// though the owner and SYSTEM still retain full control.
			system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
			if err != nil {
				t.Fatal(err)
			}
			everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
			if err != nil {
				t.Fatal(err)
			}
			entry := func(sid *windows.SID, rights windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
				return windows.EXPLICIT_ACCESS{AccessPermissions: rights, AccessMode: windows.SET_ACCESS, Inheritance: windows.NO_INHERITANCE, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(sid)}}
			}
			acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry(user.User.Sid, windows.GENERIC_ALL), entry(system, windows.GENERIC_ALL), entry(everyone, windows.GENERIC_READ)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
				t.Fatal(err)
			}
			info, err = os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = nativeJournalPermissions(path, info, directory); !errors.Is(err, ErrNativeHistoryInvalid) {
				t.Fatal("actual third-party read ACL accepted", err)
			}
			if err = nativeJournalSecure(path); err != nil {
				t.Fatal(err)
			}
			info, err = os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = nativeJournalPermissions(path, info, directory); err != nil {
				t.Fatal("restored private descriptor rejected", err)
			}
		}
	})
	t.Run("platform-dacl-format", func(t *testing.T) {
		const user = "S-1-5-21-1-2-3-1001"
		aces := "(A;;GA;;;" + user + ")(A;;FA;;;SY)"
		for _, flags := range []string{"P", "PAI", "PAR", "PARAI", "PAIAR", "AIP", "ARP", "AIARP"} {
			t.Run("valid-"+flags, func(t *testing.T) {
				if err := validateNativeJournalDACL("O:"+user+"D:"+flags+aces, user); err != nil {
					t.Fatal("private protected flags rejected", err)
				}
			})
		}
		for _, tc := range []struct{ name, text string }{
			{"unprotected", "D:AI" + aces}, {"unknown-flags", "D:PX" + aces}, {"duplicate-flags", "D:PPAI" + aces}, {"null-acl", "D:PNO_ACCESS_CONTROL"}, {"empty-acl", "D:P"}, {"missing-dacl", "O:" + user}, {"extra-dacl", "D:P" + aces + "D:P" + aces},
			{"inherited-ace", "D:P(A;ID;GA;;;" + user + ")(A;;GA;;;SY)"}, {"inheritable-ace", "D:P(A;OI;GA;;;" + user + ")(A;;GA;;;SY)"}, {"deny-ace", "D:P(D;;GA;;;" + user + ")(A;;GA;;;SY)"}, {"object-ace", "D:P(OA;;GA;;;" + user + ")(A;;GA;;;SY)"}, {"partial-rights", "D:P(A;;GR;;;" + user + ")(A;;GA;;;SY)"},
			{"extra-principal", "D:P" + aces + "(A;;GR;;;WD)"}, {"wrong-principal", "D:P(A;;GA;;;WD)(A;;GA;;;SY)"}, {"duplicate-user", "D:P(A;;GA;;;" + user + ")(A;;GA;;;" + user + ")"}, {"duplicate-system", "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-18)"}, {"guid", "D:P(A;;GA;00000000-0000-0000-0000-000000000000;;" + user + ")(A;;GA;;;SY)"},
			{"trailing", "D:P" + aces + "garbage"}, {"over-budget", strings.Repeat("x", 4097)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := validateNativeJournalDACL(tc.text, user); !errors.Is(err, ErrNativeHistoryInvalid) {
					t.Fatal("nonprivate descriptor accepted", err)
				}
			})
		}
	})
}

func nativeJournalSpecialKinds() []string { return []string{"directory", "hardlink"} }
func nativeJournalMakeSpecial(t *testing.T, path, kind string) {
	t.Helper()
	switch kind {
	case "directory":
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	case "hardlink":
		if err := os.WriteFile(path+".outside", []byte("not-a-record"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path+".outside", path); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown fixture kind")
	}
}
