package enforcer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func resolvePolicyRevisionPath(path string) (string, error) {
	if runtime.GOOS != "darwin" {
		return filepath.EvalSymlinks(path)
	}
	return resolvePolicyRevisionPathRetry(path, filepath.EvalSymlinks, os.Lstat)
}

// Darwin can transiently return readlink EINVAL while a symlink is atomically
// replaced. Retry resolution only if the reported entry is still a symlink;
// a real non-link, missing file, permission error or exhausted budget fails
// closed. No module/signature bytes are read until resolution succeeds once.
func resolvePolicyRevisionPathRetry(path string, resolve func(string) (string, error), lstat func(string) (os.FileInfo, error)) (string, error) {
	const attempts = 4
	for attempt := 0; ; attempt++ {
		resolved, err := resolve(path)
		if err == nil {
			return resolved, nil
		}
		var pe *os.PathError
		if attempt == attempts-1 || !errors.As(err, &pe) || pe.Op != "readlink" || !errors.Is(pe.Err, syscall.EINVAL) {
			return "", err
		}
		info, statErr := lstat(pe.Path)
		if statErr != nil || info.Mode()&os.ModeSymlink == 0 {
			return "", err
		}
	}
}
