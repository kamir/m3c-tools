//go:build windows

package registry

import (
	"errors"
	"os"
	"path/filepath"
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
	t.Run("platform-binary-descriptor", func(t *testing.T) {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Fatal(err)
		}
		current := user.User.Sid.String()
		foreign := "S-1-5-21-1-2-3-500"
		if current == foreign {
			foreign = "S-1-5-21-4-5-6-500"
		}
		for _, tc := range []struct {
			name, owner, flags, trustee, rights, aceFlags string
			allow                                         bool
		}{
			{"current-owner-and-trustee", current, "P", current, "FA", "", true},
			{"current-generic-all", current, "P", current, "GA", "", true},
			{"protected-PAI", current, "PAI", current, "FA", "", true},
			{"protected-PAR", current, "PAR", current, "FA", "", true},
			{"protected-PARAI", current, "PARAI", current, "FA", "", true},
			{"protected-PAIAR", current, "PAIAR", current, "FA", "", true},
			{"protected-AIP", current, "AIP", current, "FA", "", true},
			{"protected-ARP", current, "ARP", current, "FA", "", true},
			{"protected-AIARP", current, "AIARP", current, "FA", "", true},
			{"partial-binary-rights", current, "P", current, "GR", "", false},
			{"inherited-binary-ace", current, "P", current, "FA", "ID", false},
			{"inheritable-binary-ace", current, "P", current, "FA", "OI", false},
			{"duplicate-system-binary-ace", current, "P", "SY", "FA", "", false},
			{"foreign-binary-owner", foreign, "P", current, "FA", "", false},
			{"foreign-domain-administrator-trustee", current, "P", foreign, "FA", "", false},
			{"unprotected-binary-descriptor", current, "", current, "FA", "", false},
			{"world-trustee", current, "P", "WD", "FA", "", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				sd, err := windows.SecurityDescriptorFromString("O:" + tc.owner + "D:" + tc.flags + "(A;" + tc.aceFlags + ";" + tc.rights + ";;;" + tc.trustee + ")(A;;FA;;;SY)")
				if err != nil {
					t.Fatal(err)
				}
				err = validateNativeJournalDescriptor(sd, user.User.Sid)
				if tc.allow {
					if err != nil {
						t.Fatalf("current binary identity refused: descriptor=%s error=%v", sd.String(), err)
					}
				} else if !errors.Is(err, ErrNativeHistoryInvalid) {
					t.Fatalf("foreign or unprotected binary descriptor accepted: descriptor=%s error=%v", sd.String(), err)
				}
			})
		}
		t.Run("deny-ace-type", func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString("O:" + current + "D:P(D;;FA;;;" + current + ")(A;;FA;;;SY)")
			if err != nil {
				t.Fatal(err)
			}
			if err := validateNativeJournalDescriptor(sd, user.User.Sid); !errors.Is(err, ErrNativeHistoryInvalid) {
				t.Fatal("deny ACE accepted", err)
			}
		})
		if err := validateNativeJournalDescriptor(nil, user.User.Sid); !errors.Is(err, ErrNativeHistoryInvalid) {
			t.Fatal("nil descriptor accepted", err)
		}
		sd, err := windows.SecurityDescriptorFromString("O:" + current + "D:P(A;;FA;;;" + current + ")(A;;FA;;;SY)")
		if err != nil {
			t.Fatal(err)
		}
		if err := validateNativeJournalDescriptor(sd, nil); !errors.Is(err, ErrNativeHistoryInvalid) {
			t.Fatal("nil current SID accepted", err)
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
