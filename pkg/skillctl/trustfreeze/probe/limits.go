package probe

import (
	"errors"
	"fmt"
	"time"
)

// ErrLimitExceeded is wrapped whenever a probe input exceeds a limit
// (SPEC-0467 R7). Its error class is "limit_exceeded".
var ErrLimitExceeded = errors.New("probe: limit exceeded")

// Limits bound one probe run (SPEC-0467 R7). A zero field means the default.
type Limits struct {
	// Timeout of one probe run (Support and Collect together).
	Timeout time.Duration
	// MaxStdoutBytes and MaxStderrBytes cap what a command run keeps; the
	// rest is drained and counted, and the result says it was truncated.
	MaxStdoutBytes int64
	MaxStderrBytes int64
	// MaxFileBytes caps one file read and one evidence file.
	MaxFileBytes int64
	// MaxFiles caps the evidence files of one probe run.
	MaxFiles int
}

// Default limits.
const (
	DefaultTimeout        = 30 * time.Second
	DefaultMaxStdoutBytes = 1 << 20
	DefaultMaxStderrBytes = 64 << 10
	DefaultMaxFileBytes   = 1 << 20
	DefaultMaxFiles       = 64
)

// DefaultLimits returns the default limits.
func DefaultLimits() Limits {
	return Limits{
		Timeout:        DefaultTimeout,
		MaxStdoutBytes: DefaultMaxStdoutBytes,
		MaxStderrBytes: DefaultMaxStderrBytes,
		MaxFileBytes:   DefaultMaxFileBytes,
		MaxFiles:       DefaultMaxFiles,
	}
}

// WithDefaults fills every zero field with its default.
func (l Limits) WithDefaults() Limits {
	d := DefaultLimits()
	if l.Timeout == 0 {
		l.Timeout = d.Timeout
	}
	if l.MaxStdoutBytes == 0 {
		l.MaxStdoutBytes = d.MaxStdoutBytes
	}
	if l.MaxStderrBytes == 0 {
		l.MaxStderrBytes = d.MaxStderrBytes
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxFiles == 0 {
		l.MaxFiles = d.MaxFiles
	}
	return l
}

// Validate rejects negative limits.
func (l Limits) Validate() error {
	if l.Timeout < 0 || l.MaxStdoutBytes < 0 || l.MaxStderrBytes < 0 || l.MaxFileBytes < 0 || l.MaxFiles < 0 {
		return fmt.Errorf("probe: negative limit in %+v", l)
	}
	return nil
}

// clampRequest applies the limits to a command request: a request may ask
// for less than the limit, never for more.
func (l Limits) clampRequest(req CommandRequest) CommandRequest {
	l = l.WithDefaults()
	if req.MaxStdoutBytes <= 0 || req.MaxStdoutBytes > l.MaxStdoutBytes {
		req.MaxStdoutBytes = l.MaxStdoutBytes
	}
	if req.MaxStderrBytes <= 0 || req.MaxStderrBytes > l.MaxStderrBytes {
		req.MaxStderrBytes = l.MaxStderrBytes
	}
	if req.Timeout <= 0 || req.Timeout > l.Timeout {
		req.Timeout = l.Timeout
	}
	return req
}
