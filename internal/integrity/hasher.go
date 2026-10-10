package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"os"
)

const fastHashReadSize = 4096

// BinaryHash contains both full and fast hashes for a binary.
type BinaryHash struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	FastHash uint32 `json:"fast_hash"`
	Size     int64  `json:"size"`
}

// HashFile computes the full SHA-256 and fast FNV-1a hash of a file.
// The fast hash uses only the first 4KB for BPF map lookups.
func HashFile(path string) (*BinaryHash, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return hashOpenFile(f, path)
}

// hashOpenFile hashes an already-open file, reporting path in errors and in
// the returned BinaryHash.
func hashOpenFile(f *os.File, path string) (*BinaryHash, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	sha := sha256.New()
	fast := fnv.New32a()

	buf := make([]byte, 32*1024)
	totalRead := int64(0)

	for {
		n, err := f.Read(buf)
		if n > 0 {
			sha.Write(buf[:n])
			if totalRead < fastHashReadSize {
				end := int64(n)
				if totalRead+end > fastHashReadSize {
					end = fastHashReadSize - totalRead
				}
				fast.Write(buf[:end])
			}
			totalRead += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}

	return &BinaryHash{
		Path:     path,
		SHA256:   hex.EncodeToString(sha.Sum(nil)),
		FastHash: fast.Sum32(),
		Size:     info.Size(),
	}, nil
}

// FastHashBytes computes FNV-1a of up to the first 4KB of data.
func FastHashBytes(data []byte) uint32 {
	h := fnv.New32a()
	if len(data) > fastHashReadSize {
		h.Write(data[:fastHashReadSize])
	} else {
		h.Write(data)
	}
	return h.Sum32()
}

// FastHashPath computes FNV-1a of a path string (for map key derivation).
func FastHashPath(path string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(path))
	return h.Sum32()
}
