// Package cliflag holds small helpers shared by the warmor command-line
// tools on top of the standard flag package.
package cliflag

import "flag"

// ParseInterspersed parses flags that may appear before, between or after
// positional arguments (Go's flag package stops at the first positional)
// and returns the positionals in order. A "--" ends flag parsing; every
// argument after it is positional.
func ParseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(positional, rest...), nil
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}
