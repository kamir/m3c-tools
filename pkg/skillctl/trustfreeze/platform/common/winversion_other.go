//go:build !windows

package common

// DefaultWindowsVersionReader returns a reader that reports ErrNotApplicable:
// there is no Windows registry on this platform. The mapping of registry
// values (winversion.go) is the same on every OS; fixture tests drive it
// through their own reader.
func DefaultWindowsVersionReader() WindowsVersionReader { return notApplicableReader{} }

type notApplicableReader struct{}

func (notApplicableReader) Read() (OSInfo, error) { return OSInfo{}, ErrNotApplicable }

// nativeArch reports ErrNotApplicable: the Windows native machine source
// does not exist on this platform.
func (notApplicableReader) nativeArch() (string, error) { return "", ErrNotApplicable }
