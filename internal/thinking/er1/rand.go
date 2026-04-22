package er1

import (
	"crypto/rand"
	"io"
)

// newRandReader returns the package-level crypto-random source used
// for nonce generation. Extracted into its own file so tests can
// monkey-patch via a build-tag if needed.
func newRandReader() io.Reader { return rand.Reader }
