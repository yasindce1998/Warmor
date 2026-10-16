package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// parseByteSize parses sizes like "4MiB", "512KiB", "1048576" (bytes) for
// --lsm-ringbuf-size. Binary suffixes only: ring sizes must be powers of two.
func parseByteSize(s string) (uint32, error) {
	units := []struct {
		suffix string
		mult   uint64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}
	num, mult := strings.TrimSpace(s), uint64(1)
	for _, u := range units {
		if strings.HasSuffix(num, u.suffix) {
			num, mult = strings.TrimSpace(strings.TrimSuffix(num, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid size %q (want e.g. 4MiB)", s)
	}
	if n > math.MaxUint32/mult {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	v := n * mult
	if v&(v-1) != 0 {
		return 0, fmt.Errorf("size %q must be a power of two", s)
	}
	return uint32(v), nil
}
