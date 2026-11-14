// warmor-policy-host is the dedicated, opt-in supervised WASM worker. It is
// not a daemon self-exec mode. Its only internal argument selects the serving
// stage after Linux descriptor sanitization and re-exec of this same binary.
package main

import (
	"os"

	"github.com/yasindce1998/warmor/internal/policyhost/worker"
)

func main() {
	if len(os.Args) == 1 {
		bootstrap()
		// bootstrap must replace the process or terminate it. Never proceed to
		// IPC if descriptor sanitization or the second exec failed.
		os.Exit(1)
	}
	if len(os.Args) != 2 || os.Args[1] != "--serve" {
		os.Exit(2)
	}
	if err := worker.Run(os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
