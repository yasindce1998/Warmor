package integrity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxSymlinks bounds symlink resolution, matching Linux's MAXSYMLINKS.
const maxSymlinks = 40

// HashFileInRoot hashes name, a rootfs-absolute path such as "/bin/sh", as
// seen from inside rootfs. Symlinks are resolved the way the kernel would
// after chroot(rootfs): absolute targets are re-anchored at rootfs and ".."
// never climbs above it, so a link can never make us hash a host file.
func HashFileInRoot(rootfs, name string) (*BinaryHash, error) {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return nil, fmt.Errorf("open rootfs %s: %w", rootfs, err)
	}
	defer root.Close()
	return hashInRoot(root, name)
}

func hashInRoot(root *os.Root, name string) (*BinaryHash, error) {
	resolved, err := resolveInRoot(root, name)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	// os.Root refuses to leave the root even if the tree changes between
	// resolution and open.
	f, err := root.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	return hashOpenFile(f, name)
}

// resolveInRoot resolves every symlink in name relative to root and returns
// a root-relative path containing no symlinks.
func resolveInRoot(root *os.Root, name string) (string, error) {
	pending := splitSlash(name)
	var resolved []string
	links := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}

		cur := filepath.Join(append(resolved, c)...)
		info, err := root.Lstat(cur)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = append(resolved, c)
			continue
		}

		links++
		if links > maxSymlinks {
			return "", fmt.Errorf("too many levels of symbolic links")
		}
		target, err := root.Readlink(cur)
		if err != nil {
			return "", err
		}
		if vol := filepath.VolumeName(target); vol != "" || strings.HasPrefix(filepath.ToSlash(target), "/") {
			// Absolute target: re-anchor at the rootfs.
			target = target[len(vol):]
			resolved = resolved[:0]
		}
		pending = append(splitSlash(target), pending...)
	}
	if len(resolved) == 0 {
		return ".", nil
	}
	return filepath.Join(resolved...), nil
}

func splitSlash(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}
