package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestAbsolutizePathFlags(t *testing.T) {
	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	in := []string{"--policy", "p.wasm", "-tls-ca=ca.pem", "--audit", "--metrics-port", "9090", "--tls-key", "k.pem"}
	want := []string{"--policy", abs("p.wasm"), "--tls-ca=" + abs("ca.pem"), "--audit", "--metrics-port", "9090", "--tls-key", abs("k.pem")}
	got, err := absolutizePathFlags(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("absolutizePathFlags = %q, want %q", got, want)
	}
}
