// recorder_stub.go — Stubs for platforms without PortAudio support.
//
//go:build !darwin

package recorder

import (
	"fmt"
	"time"
)

var errUnsupported = fmt.Errorf("audio recording not supported on this platform (requires macOS with PortAudio)")

// ListInputDevices is not available on this platform.
func ListInputDevices() ([]DeviceInfo, error) {
	return nil, errUnsupported
}

// Record is not available on this platform.
func Record(seconds int) ([]int16, error) {
	return nil, errUnsupported
}

// RecordTimed is not available on this platform.
func RecordTimed(duration time.Duration) ([]byte, error) {
	return nil, errUnsupported
}

// RecordUntilStop is not available on this platform.
func RecordUntilStop(stop <-chan struct{}, maxSeconds int) ([]int16, error) {
	return nil, errUnsupported
}

// RecordTimedWithStop is not available on this platform.
func RecordTimedWithStop(stop <-chan struct{}, maxSeconds int) ([]byte, error) {
	return nil, errUnsupported
}

// RecordWithLevels is not available on this platform.
func RecordWithLevels(stop <-chan struct{}, maxSeconds int, onLevel LevelCallback) ([]int16, error) {
	return nil, errUnsupported
}
