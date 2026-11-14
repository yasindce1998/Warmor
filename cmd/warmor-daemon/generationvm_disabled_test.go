//go:build !linux || !integration || !generation_daemon_vm

package main

import (
	"flag"
	"testing"
)

func TestGenerationVMControlsAbsentFromRelease(t *testing.T) {
	if flag.Lookup("generation-vm-control") != nil {
		t.Fatal("VM fault controls must not exist in normal daemon builds")
	}
}
