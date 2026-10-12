// Package winutil holds Windows platform helpers shared by the ETW consumer
// and the eBPF-for-Windows loader: the process table, NT device path
// translation, image hashing and command-line splitting.
//
// Everything outside the *_windows.go files is portable Go so it can be unit
// tested on any OS.
package winutil

import "strings"

// CommFromPath returns the lowercased file name of an image path, which is
// what Windows policies match "comm" against ("powershell.exe"). Windows
// file names are case-insensitive, so lowercasing keeps "PowerShell.EXE"
// from slipping past a rule written as "powershell.exe".
func CommFromPath(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		path = path[i+1:]
	}
	return strings.ToLower(path)
}

// SplitCommandLine splits a Windows command line into arguments using the
// same rules as CommandLineToArgvW / the MSVC runtime:
//
//   - arguments are separated by spaces or tabs outside quotes
//   - 2n backslashes followed by a quote produce n backslashes and toggle quoting
//   - 2n+1 backslashes followed by a quote produce n backslashes and a literal quote
//   - backslashes not followed by a quote are literal
//   - inside quotes, "" produces a literal quote
//
// The first argument (the program name) is special-cased like
// CommandLineToArgvW: it ends at the first space/tab outside quotes and
// backslashes in it are always literal.
func SplitCommandLine(cmd string) []string {
	var args []string
	i := 0
	n := len(cmd)

	// Program name.
	if n == 0 {
		return nil
	}
	var b strings.Builder
	inQuotes := false
	for ; i < n; i++ {
		c := cmd[i]
		if c == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && (c == ' ' || c == '\t') {
			break
		}
		b.WriteByte(c)
	}
	args = append(args, b.String())

	for {
		for i < n && (cmd[i] == ' ' || cmd[i] == '\t') {
			i++
		}
		if i >= n {
			return args
		}

		b.Reset()
		inQuotes = false
		for i < n {
			c := cmd[i]
			if !inQuotes && (c == ' ' || c == '\t') {
				break
			}
			switch {
			case c == '\\':
				slashes := 0
				for i < n && cmd[i] == '\\' {
					slashes++
					i++
				}
				if i < n && cmd[i] == '"' {
					b.WriteString(strings.Repeat(`\`, slashes/2))
					if slashes%2 == 1 {
						b.WriteByte('"')
						i++
					}
					// Even count: the quote is handled on the next iteration.
				} else {
					b.WriteString(strings.Repeat(`\`, slashes))
				}
			case c == '"':
				if inQuotes && i+1 < n && cmd[i+1] == '"' {
					b.WriteByte('"')
					i += 2
					continue
				}
				inQuotes = !inQuotes
				i++
			default:
				b.WriteByte(c)
				i++
			}
		}
		args = append(args, b.String())
	}
}
