// Package globcorpus holds the single glob test corpus shared by the Go
// matcher tests (internal/patterns) and the compiled-Rust/WASM tests
// (internal/compiler). Both must agree on every case.
package globcorpus

// Case is one (pattern, path, want-match) triple.
type Case struct {
	Name    string
	Pattern string
	Path    string
	Want    bool
}

// Cases is the shared glob corpus. It includes the four user-reported
// divergent cases, separator rules, '**' boundary rules, multiple '**'
// segments, classes, escapes and UTF-8 runes.
var Cases = []Case{
	// Basic filepath.Match-style behavior.
	{"exact", "/bin/bash", "/bin/bash", true},
	{"exact-miss", "/bin/bash", "/bin/sh", false},
	{"star-single-segment", "/tmp/*.sh", "/tmp/script.sh", true},
	{"star-crosses-separator-rejected", "/tmp/*.sh", "/tmp/a/b/evil.sh", false},
	{"star-empty-segment", "/tmp/*", "/tmp/", true},
	{"star-requires-segment", "/tmp/*", "/tmp", false},
	{"question", "/bin/bas?", "/bin/bash", true},
	{"question-crosses-separator-rejected", "/bin/bas?", "/bin/ba/sh", false},
	{"question-single-rune", "/tmp/?.sh", "/tmp/é.sh", true},
	{"question-two-runes", "/tmp/??.sh", "/tmp/é.sh", false},
	{"class", "/bin/[bs]ash", "/bin/bash", true},
	{"class-negated", "/bin/[^b]ash", "/bin/dash", true},
	{"class-negated-miss", "/bin/[^b]ash", "/bin/bash", false},
	{"class-utf8", "/tmp/[é].sh", "/tmp/é.sh", true},
	{"class-malformed", "/bin/[bs", "/bin/b", false},
	{"escape", `/tmp/a\*b`, `/tmp/a*b`, true},
	{"escape-miss", `/tmp/a\*b`, `/tmp/axb`, false},

	// ** boundary rules.
	{"doublestar-crosses-separator", "/tmp/**", "/tmp/a/b", true},
	{"doublestar-excludes-base", "/tmp/**", "/tmp", false},
	{"doublestar-empty-after-slash", "/tmp/**", "/tmp/", true},
	{"doublestar-middle-foox-rejected", "/tmp/**/x.sh", "/tmp/foox.sh", false},
	{"doublestar-middle-zero-segments", "/tmp/**/x.sh", "/tmp/x.sh", true},
	{"doublestar-middle-one-segment", "/tmp/**/x.sh", "/tmp/a/x.sh", true},
	{"doublestar-middle-many-segments", "/tmp/**/x.sh", "/tmp/a/b/x.sh", true},
	{"doublestar-middle-suffix-boundary", "/tmp/**/x.sh", "/tmp/a/foox.sh", false},
	{"doublestar-prefix-rune-boundary-rejected", "/home/**/.ssh/**", "/home/bob/x.ssh/id", false},
	{"doublestar-prefix-boundary", "/home/**/.ssh/**", "/home/bob/.ssh/id", true},
	{"doublestar-prefix-zero-segments", "/home/**/.ssh/**", "/home/.ssh/id", true},
	{"doublestar-leading-zero-segments", "**/x.sh", "x.sh", true},
	{"doublestar-leading-many-segments", "**/x.sh", "/tmp/a/x.sh", true},
	{"doublestar-only", "**", "/tmp/a/x.sh", true},
	{"doublestar-only-empty", "**", "", true},
	{"doublestar-trailing-dir-not-base", "/etc/cron.*/**", "/etc/cron.daily", false},
	{"doublestar-trailing-dir", "/etc/cron.*/**", "/etc/cron.daily/job", true},

	// Multiple ** segments and non-segment ** fallbacks.
	{"two-doublestars-zero", "/usr/local/nvidia/**/../../../**", "/usr/local/nvidia/../../../x", true},
	{"two-doublestars-one", "/usr/local/nvidia/**/../../../**", "/usr/local/nvidia/lib/../../../x", true},
	{"doublestar-plus-star", "/usr/lib/**/libnvidia*.so*", "/usr/lib/libnvidia1.so.2", true},
	{"doublestar-plus-star-nested", "/usr/lib/**/libnvidia*.so*", "/usr/lib/a/b/libnvidia1.so.2", true},
	{"doublestar-plus-star-miss", "/usr/lib/**/libnvidia*.so*", "/usr/lib/a/b/libgl.so", false},
	{"doublestar-not-segment", "a**b", "axb", true},
	{"doublestar-not-segment-crosses-rejected", "a**b", "a/x/b", false},
}
