// warmor-policy-host is the dedicated, opt-in supervised WASM worker. It is
// not a daemon self-exec mode and has no command-line configuration.
package main

import (
	"os"

	"github.com/yasindce1998/warmor/internal/policyhost/worker"
)

func main() {
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	// fd 3 pins the trusted executable during exec; it is not an IPC channel.
	if f := os.NewFile(3, "executable"); f != nil {
		_ = f.Close()
	}
	if err := worker.Run(os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
