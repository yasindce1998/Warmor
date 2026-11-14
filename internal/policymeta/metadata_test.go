package policymeta

import (
	"bytes"
	"testing"
)

func TestMetadataRoundTripAndMalformed(t *testing.T) {
	header := []byte{0, 97, 115, 109, 1, 0, 0, 0}
	m := Metadata{Compiler: "test-build", DefaultAction: "deny"}
	module, err := Append(header, m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(module)
	if err != nil || *got != m {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := Append(module, m); err == nil {
		t.Fatal("duplicate appended")
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(module), 0, 0xff), append(bytes.Clone(module), module[8:]...), bytes.Replace(module, []byte(`"deny"`), []byte(`"oops"`), 1)} {
		if _, err := Read(bad); err == nil {
			t.Fatal("malformed metadata accepted")
		}
	}
	for i := 9; i < len(module); i++ {
		if _, err := Read(module[:i]); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{0, 97, 115, 109, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Read(data) })
}
