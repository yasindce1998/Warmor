//go:build linux && integration && generation_daemon_vm

package main

import (
	"flag"

	"github.com/yasindce1998/warmor/internal/generationvm"
)

var generationVMControl = flag.String("generation-vm-control", "", "TEST PROFILE ONLY: vimto-guarded generation fault/evidence directory")

func setupGenerationVM() error {
	if *generationVMControl == "" {
		return nil
	}
	return generationvm.Init(*generationVMControl)
}
