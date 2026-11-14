//go:build linux

package policyhost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func supported() error { return nil }

// Walk using directory descriptors and O_NOFOLLOW: validation must apply to
// the inode actually executed, not an earlier pathname lookup. Root-owned
// sticky directories (e.g. /tmp) may contain an owner-only staging directory.
func openRegular(path string, executable bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("policy-host path must be clean and absolute")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { unix.Close(dir) }()
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, errors.New("unsafe policy-host directory")
		}
		unix.Close(dir)
		dir = next
		if executable {
			var st unix.Stat_t
			if unix.Fstat(dir, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
				return nil, errors.New("untrusted policy-host directory")
			}
		}
	}
	fd, err := unix.Openat(dir, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot open policy-host file")
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		f.Close()
		return nil, errors.New("policy-host file must be regular")
	}
	if executable && ((st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0022 != 0 || st.Mode&0111 == 0 || st.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 || st.Size > 128<<20) {
		f.Close()
		return nil, errors.New("untrusted policy-host executable")
	}
	return f, nil
}

func readRegular(path string, max int64) ([]byte, error) {
	f, err := openRegular(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, errors.New("cannot read policy staging file")
	}
	if int64(len(b)) > max {
		return nil, errors.New("policy staging size limit")
	}
	return b, nil
}

func trustedExecutable(path, digest string) (*os.File, error) {
	if len(digest) != 64 {
		return nil, errors.New("policy-host executable SHA-256 required")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || hex.EncodeToString(decoded) != digest {
		return nil, errors.New("invalid policy-host executable SHA-256")
	}
	f, err := openRegular(path, true)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if err != nil || n > 128<<20 || hex.EncodeToString(h.Sum(nil)) != digest {
		f.Close()
		return nil, errors.New("policy-host executable digest mismatch")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func command(f *os.File) *exec.Cmd {
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Args = []string{"warmor-policy-host"}
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"GOMAXPROCS=1"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	return cmd
}

// Only this owned child is signaled; there is no fork/exec host import and the
// worker does not start subprocesses. os.Process uses a pidfd where available.
func kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
