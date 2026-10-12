package winutil

import "unicode/utf16"

// ImagePathMaxChars is the size, in UTF-16 code units, of the buffer the
// eBPF process hook reads bpf_process_get_image_path into
// (WARMOR_IMAGE_PATH_CHARS in bpf-windows/warmor_efw.h). One unit is kept for
// the terminating NUL, and the kernel stores hash 0 for paths that fill the
// rest, since they may have been truncated, so such paths are never matchable
// in the kernel.
const ImagePathMaxChars = 512

const (
	fnv64Offset = 14695981039346656037
	fnv64Prime  = 1099511628211
)

// ImageHash returns the 64-bit FNV-1a hash the eBPF programs compute over an
// NT image path: each UTF-16 code unit is ASCII-lowercased, then hashed low
// byte first. It returns 0 for paths the kernel cannot hash in full.
//
// Must stay in sync with warmor_image_hash() in bpf-windows/warmor_efw.h.
func ImageHash(ntPath string) uint64 {
	units := utf16.Encode([]rune(ntPath))
	if len(units) == 0 || len(units) >= ImagePathMaxChars-1 {
		return 0
	}
	h := uint64(fnv64Offset)
	for _, u := range units {
		if u >= 'A' && u <= 'Z' {
			u += 'a' - 'A'
		}
		h ^= uint64(u & 0xff)
		h *= fnv64Prime
		h ^= uint64(u >> 8)
		h *= fnv64Prime
	}
	if h == 0 {
		// 0 means "unknown image" to the kernel; never collide with it.
		h = 1
	}
	return h
}
