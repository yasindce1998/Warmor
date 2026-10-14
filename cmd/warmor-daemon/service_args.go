package main

import (
	"path/filepath"
	"strings"
)

// absolutizePathFlags rewrites path-valued daemon flags to absolute paths:
// services start in %SystemRoot%\System32, so relative paths would resolve
// there instead of where the operator ran install.
func absolutizePathFlags(args []string) ([]string, error) {
	pathFlags := map[string]bool{"policy": true, "tls-ca": true, "tls-cert": true, "tls-key": true, "verify-key": true}
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := strings.TrimLeft(a, "-")
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
			continue
		}
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			if pathFlags[name[:eq]] {
				abs, err := filepath.Abs(name[eq+1:])
				if err != nil {
					return nil, err
				}
				a = "--" + name[:eq] + "=" + abs
			}
			out = append(out, a)
			continue
		}
		out = append(out, a)
		if pathFlags[name] && i+1 < len(args) {
			abs, err := filepath.Abs(args[i+1])
			if err != nil {
				return nil, err
			}
			out = append(out, abs)
			i++
		}
	}
	return out, nil
}
