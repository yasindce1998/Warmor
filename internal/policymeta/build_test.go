package policymeta_test

import (
	"bytes"
	"github.com/yasindce1998/warmor/internal/policybuild"
	. "github.com/yasindce1998/warmor/internal/policymeta"
	"strings"
	"testing"
)

func TestSignedBuildFormatCompatibility(t *testing.T) {
	header := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	build := policybuild.Metadata{Compiler: "test-build", DefaultAction: "deny"}
	module, err := policybuild.Append(header, build)
	if err != nil {
		t.Fatal(err)
	}
	got, err := policybuild.Read(module)
	if err != nil || got == nil || *got != build {
		t.Fatalf("build round trip %+v %v", got, err)
	}
	// Exact existing signed-activation format: same custom section name and
	// canonical lower-case JSON keys, no alternate observation envelope.
	payload := []byte(`{"compiler":"test-build","default_action":"deny"}`)
	section := append([]byte{byte(len(policybuild.Section))}, []byte(policybuild.Section)...)
	section = append(section, payload...)
	want := append(bytes.Clone(header), 0, byte(len(section)))
	want = append(want, section...)
	if !bytes.Equal(module, want) {
		t.Fatal("signed format changed")
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(module), 0, 0xff), append(bytes.Clone(module), module[8:]...), bytes.Replace(module, []byte(`"deny"`), []byte(`"oops"`), 1)} {
		if _, err := policybuild.Read(bad); err == nil {
			t.Fatal("malformed build metadata accepted")
		}
	}
	if _, err := policybuild.Append(module, build); err == nil {
		t.Fatal("duplicate metadata appended")
	}
	for i := 9; i < len(module); i++ {
		if _, err := policybuild.Read(module[:i]); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
}

func TestMatchArtifactDoesNotAuthorizeOptimization(t *testing.T) {
	digest := strings.Repeat("a", 64)
	m := Observe(digest, 5, EncodingBinary, [3]uint32{0, 0, 0}, StaticDomain{}, StaticDomain{})
	if m.MatchArtifact(digest, 5, "build", "deny") == nil {
		t.Fatal("missing build metadata accepted")
	}
	m.Build = &policybuild.Metadata{Compiler: "build", DefaultAction: "deny"}
	if err := m.MatchArtifact(digest, 5, "build", "deny"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		digest           string
		abi              uint32
		compiler, action string
	}{{strings.Repeat("b", 64), 5, "build", "deny"}, {digest, 3, "build", "deny"}, {digest, 5, "other", "deny"}, {digest, 5, "build", "allow"}, {digest, 0, "build", "deny"}} {
		if m.MatchArtifact(tc.digest, tc.abi, tc.compiler, tc.action) == nil {
			t.Fatal("mismatch accepted")
		}
	}
	clone := m.Clone()
	clone.Build.Compiler = "other"
	if m.Build.Compiler != "build" {
		t.Fatal("build snapshot aliases source")
	}
	for _, b := range []policybuild.Metadata{{Compiler: "", DefaultAction: "deny"}, {Compiler: "build\x00label", DefaultAction: "deny"}, {Compiler: "build", DefaultAction: "unknown"}} {
		if ValidateBuild(b) == nil {
			t.Fatal("invalid build fields accepted")
		}
	}
}

func FuzzBuildRead(f *testing.F) {
	f.Add([]byte{0, 97, 115, 109, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = policybuild.Read(data) })
}
