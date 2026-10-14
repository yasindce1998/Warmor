package cliflag

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantPos []string
		wantO   string
		wantV   bool
	}{
		{"flags first", []string{"-o", "x.wasm", "in.yaml"}, []string{"in.yaml"}, "x.wasm", false},
		{"flags last", []string{"in.yaml", "-o", "x.wasm", "--v"}, []string{"in.yaml"}, "x.wasm", true},
		{"flags between", []string{"a", "-o=x", "b"}, []string{"a", "b"}, "x", false},
		{"stdin dash", []string{"-", "-v"}, []string{"-"}, "", true},
		{"double dash", []string{"a", "--", "-o", "b"}, []string{"a", "-o", "b"}, "", false},
		{"none", nil, nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			o := fs.String("o", "", "")
			v := fs.Bool("v", false, "")
			pos, err := ParseInterspersed(fs, tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(pos, tt.wantPos) || *o != tt.wantO || *v != tt.wantV {
				t.Errorf("got pos=%q o=%q v=%v, want pos=%q o=%q v=%v", pos, *o, *v, tt.wantPos, tt.wantO, tt.wantV)
			}
		})
	}
}

func TestParseInterspersed_Error(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if _, err := ParseInterspersed(fs, []string{"a", "-unknown"}); err == nil {
		t.Fatal("expected error for unknown trailing flag")
	}
}
