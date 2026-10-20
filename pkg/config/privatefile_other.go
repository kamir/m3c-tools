//go:build !windows

package config

import "os"

func createPrivateTemp(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".private-*")
}
