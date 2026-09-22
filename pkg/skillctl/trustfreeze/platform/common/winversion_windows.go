//go:build windows

package common

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// DefaultWindowsVersionReader returns the registry reader. It opens
// WindowsCurrentVersionKey read-only (KEY_QUERY_VALUE and nothing else) in
// the 64-bit registry view (KEY_WOW64_64KEY, so a 32-bit build on 64-bit
// Windows reads the same key), reads the values named in winversion.go and
// maps them with windowsVersionFromValues. It never writes, never enumerates
// and never requests elevation.
func DefaultWindowsVersionReader() WindowsVersionReader { return registryVersionReader{} }

type registryVersionReader struct{}

// Read implements WindowsVersionReader.
func (r registryVersionReader) Read() (OSInfo, error) {
	v, err := r.readDetail()
	return v.Info, err
}

// readDetail reads and maps the value set. A key that does not exist
// matches fs.ErrNotExist (the probe reports unavailable); access denied
// matches fs.ErrPermission (permission_denied). The registry keeps security
// descriptors per key, not per value, so a key that opens normally lets
// every value be read; per-value errors are still classified the same way.
func (registryVersionReader) readDetail() (windowsVersion, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, winCurrentVersionSubkey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return windowsVersion{}, winRegistryError("open "+WindowsCurrentVersionKey, err)
	}
	defer k.Close()

	values := map[string]winRegValue{}
	for _, name := range winStringValueNames {
		s, typ, err := k.GetStringValue(name)
		if v, ok := winValueOutcome(name, typ, err); ok {
			v.Str = s
			values[name] = v
		}
	}
	n, typ, err := k.GetIntegerValue(winValueUBR)
	if v, ok := winValueOutcome(winValueUBR, typ, err); ok {
		v.Num = n
		values[winValueUBR] = v
	}
	return windowsVersionFromValues(values)
}

// winValueOutcome classifies the result of one Get*Value call. ok is false
// when the value does not exist. A value of another type is kept with its
// type and no data; the mapping reports the mismatch.
func winValueOutcome(name string, typ uint32, err error) (winRegValue, bool) {
	switch {
	case err == nil:
		return winRegValue{Type: typ}, true
	case errors.Is(err, registry.ErrNotExist):
		return winRegValue{}, false
	case errors.Is(err, registry.ErrUnexpectedType):
		return winRegValue{Type: typ}, true
	}
	return winRegValue{Type: typ, Err: winRegistryError("read "+name, err)}, true
}

// winRegistryError attaches the Win32 error code of err, if any.
func winRegistryError(op string, err error) error {
	var code uint32
	var errno syscall.Errno
	if errors.As(err, &errno) {
		code = uint32(errno)
	}
	return newWinRegError(op, code, err)
}

// nativeArch returns the native machine architecture of the host from
// IsWow64Process2 (Windows 10 1511 and later). Its nativeMachine is the
// machine of the host also for an x86 process under WOW64 and an x64 process
// under emulation on arm64, unlike runtime.GOARCH and the process
// environment. It reads nothing else and needs no privilege.
func (registryVersionReader) nativeArch() (string, error) {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err != nil {
		return "", fmt.Errorf("IsWow64Process2: %w", err)
	}
	return winMachineArch(native)
}
