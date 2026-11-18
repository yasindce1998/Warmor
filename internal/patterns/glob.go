package patterns

import (
	"unicode/utf8"
)

// This file implements the glob semantics shared by the Go matcher and the
// generated Rust policy matcher (internal/compiler/codegen.go). Keep the two
// algorithms in sync: any change here must be mirrored there.
//
// Semantics (anchored, filepath.Match-style):
//   - '/' is the only path separator. '*' and '?' never cross it.
//   - '*' matches zero or more characters in one segment; '?' matches one.
//   - '[...]', '[^...]', ranges and '\' escapes behave like filepath.Match.
//   - '**' is recursive only when it is a whole segment (delimited by '/' or
//     the pattern boundaries). It matches zero or more whole segments.
//     A '/' immediately before '**' is literal, so "/tmp/**" does not match
//     "/tmp"; a '/' immediately after '**' may be skipped when '**' matches
//     zero segments, so "/tmp/**/x.sh" matches "/tmp/x.sh".
//   - A '**' that is not a whole segment (e.g. "a**b") is two ordinary '*'s.
//
// BACKWARD COMPATIBILITY: the generated Rust matcher previously let '*' and
// '?' cross '/' and handled '**' ad hoc. Compiled policies could therefore
// match paths that the Go matcher rejected (e.g. /tmp/*.sh matched
// /tmp/a/b/evil.sh). Both matchers now use these rules, which narrows some
// allow/deny glob rules. Review policies with globs before upgrading.

// globMaxPattern bounds the bitset used by the NFA simulation. Patterns longer
// than this are rejected (never match) so the matcher stays allocation-bounded.
const globMaxPattern = 1024

// matchGlob reports whether the whole path matches pattern.
func matchGlob(pattern, path string) bool {
	if len(pattern) > globMaxPattern {
		return false
	}
	p := []byte(pattern)
	s := []byte(path)
	words := len(p)/64 + 1 // bits 0..=len(p) inclusive
	cur := make([]uint64, words)
	next := make([]uint64, words)
	globSet(cur, 0)
	globClosure(p, cur)
	for si := 0; si < len(s); {
		r, n := utf8.DecodeRune(s[si:])
		if n == 0 {
			break
		}
		for w := range next {
			next[w] = 0
		}
		for pi := 0; pi <= len(p); pi++ {
			if !globGet(cur, pi) || pi == len(p) {
				continue
			}
			switch {
			case globIsDoubleStarStart(p, pi):
				// '**' entry state: consuming a rune (including '/') moves to
				// the running state at the second star.
				globSet(next, pi+1)
			case globIsDoubleStarRunning(p, pi):
				// '**' running state: it can keep consuming any rune; the
				// closure lets it stop at any boundary.
				globSet(next, pi)
			case p[pi] == '*':
				if r != '/' {
					globSet(next, pi)
				}
			case p[pi] == '?':
				if r != '/' {
					globSet(next, pi+1)
				}
			case p[pi] == '[':
				if end, ok := globClassEnd(p, pi); ok && r != '/' && globClassMatch(p, pi, end, r) {
					globSet(next, end)
				}
			case p[pi] == '\\':
				if pr, pn := globPatternRune(p, pi+1); pr == r && pn > 0 {
					globSet(next, pi+1+pn)
				}
			default:
				if pr, pn := globPatternRune(p, pi); pr == r && pn > 0 {
					globSet(next, pi+pn)
				}
			}
		}
		globClosure(p, next)
		cur, next = next, cur
		si += n
	}
	return globGet(cur, len(p))
}

// globClosure applies the epsilon moves: a wildcard may always match zero
// characters. All moves advance the pattern index, so one ascending pass is
// enough and the closure cannot loop.
func globClosure(p []byte, bits []uint64) {
	for pi := 0; pi < len(p); pi++ {
		if !globGet(bits, pi) || p[pi] != '*' {
			continue
		}
		switch {
		case globIsDoubleStarStart(p, pi):
			// '**' matched zero bytes; its following '/' may be skipped
			// only here, before any rune has been consumed.
			globSet(bits, pi+2)
			if pi+2 < len(p) && p[pi+2] == '/' {
				globSet(bits, pi+3)
			}
		case globIsDoubleStarRunning(p, pi):
			// After consuming at least one rune, '**' must stop at the
			// literal '/' that follows it (if any).
			globSet(bits, pi+1)
		default:
			globSet(bits, pi+1)
		}
	}
}

// globIsDoubleStarStart reports whether p[pi:] starts with a recursive '**':
// two stars forming an entire path segment. pi is the entry state; pi+1 is
// reserved as the "already consumed a rune" state.
func globIsDoubleStarStart(p []byte, pi int) bool {
	return pi+1 < len(p) && p[pi] == '*' && p[pi+1] == '*' &&
		(pi == 0 || p[pi-1] == '/') &&
		(pi+2 == len(p) || p[pi+2] == '/')
}

// globIsDoubleStarRunning reports whether pi is the second star of a
// recursive '**' that has already consumed at least one rune.
func globIsDoubleStarRunning(p []byte, pi int) bool {
	return pi > 0 && p[pi] == '*' && globIsDoubleStarStart(p, pi-1)
}

// globPatternRune decodes one rune of the pattern at i. Invalid encodings
// decode as utf8.RuneError with width 1, matching filepath.Match.
func globPatternRune(p []byte, i int) (rune, int) {
	if i >= len(p) {
		return utf8.RuneError, 0
	}
	r, n := utf8.DecodeRune(p[i:])
	return r, n
}

// globGetEsc mirrors filepath.Match's getEsc: '-' and ']' cannot start a
// range, and a trailing backslash is a bad pattern.
func globGetEsc(p []byte, i, end int) (rune, int, bool) {
	if i >= end || p[i] == '-' || p[i] == ']' {
		return 0, 0, false
	}
	if p[i] == '\\' {
		i++
		if i >= end {
			return 0, 0, false
		}
	}
	r, n := utf8.DecodeRune(p[i:end])
	if r == utf8.RuneError && n == 1 {
		return 0, 0, false
	}
	return r, n, true
}

// globClassEnd returns the byte index just past the closing ']' of the
// character class at pi, or false if the class is malformed.
func globClassEnd(p []byte, pi int) (int, bool) {
	i := pi + 1
	if i < len(p) && p[i] == '^' {
		i++
	}
	nrange := 0
	for i < len(p) {
		if p[i] == ']' && nrange > 0 {
			return i + 1, true
		}
		_, n, ok := globGetEsc(p, i, len(p))
		if !ok {
			return 0, false
		}
		i += n
		if i < len(p) && p[i] == '-' {
			_, n, ok = globGetEsc(p, i+1, len(p))
			if !ok {
				return 0, false
			}
			i += 1 + n
		}
		nrange++
	}
	return 0, false
}

// globClassMatch reports whether r is in the class spanning p[pi:end].
func globClassMatch(p []byte, pi, end int, r rune) bool {
	i := pi + 1
	negated := false
	if i < end && p[i] == '^' {
		negated = true
		i++
	}
	matched := false
	nrange := 0
	for i < end {
		if p[i] == ']' && nrange > 0 {
			break
		}
		lo, n, ok := globGetEsc(p, i, end)
		if !ok {
			return false
		}
		i += n
		hi := lo
		if i < end && p[i] == '-' {
			hi, n, ok = globGetEsc(p, i+1, end)
			if !ok {
				return false
			}
			i += 1 + n
		}
		if lo <= r && r <= hi {
			matched = true
		}
		nrange++
	}
	return matched != negated
}

func globSet(bits []uint64, i int) {
	bits[i/64] |= 1 << uint(i%64)
}

func globGet(bits []uint64, i int) bool {
	return bits[i/64]&(1<<uint(i%64)) != 0
}
