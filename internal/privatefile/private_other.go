//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package privatefile

import (
	"fmt"
	"os"
)

// Fail closed where POSIX permission/no-follow guarantees are unavailable.
func OpenAppend(path string, privateDir, createDirs bool) (*os.File, error) {
	return nil, fmt.Errorf("private event recording is unsupported on this platform")
}

func Rotate(path, archive string, file *os.File) error {
	return fmt.Errorf("private event recording is unsupported on this platform")
}
