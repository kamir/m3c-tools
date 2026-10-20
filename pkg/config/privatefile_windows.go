//go:build windows

package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createPrivateTemp(dir string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("query private file owner: %w", err)
	}
	// The protected descriptor is supplied to CREATE_NEW itself. Changing an
	// inherited DACL after creation would leave an opening for another user to
	// acquire a readable handle before the first secret byte is written.
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)")
	if err != nil {
		return nil, fmt.Errorf("build private file permissions: %w", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	for range 32 {
		path := filepath.Join(dir, ".private-"+rand.Text())
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			&attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				continue
			}
			return nil, fmt.Errorf("create protected private file: %w", err)
		}
		file := os.NewFile(uintptr(handle), path)
		if file == nil {
			return nil, errors.Join(errors.New("invalid private file handle"), windows.CloseHandle(handle), os.Remove(path))
		}
		return file, nil
	}
	return nil, fmt.Errorf("create protected private file: collision retry limit: %w", os.ErrExist)
}
