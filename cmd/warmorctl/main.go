package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	serverURL = flag.String("server", "http://localhost:8443", "Policy server URL")
	jwtToken  = flag.String("token", "", "JWT bearer token with the admin role for the admin API (default $WARMOR_TOKEN)")
	caCert    = flag.String("ca-cert", "", "CA certificate PEM used to verify the policy server (default: system roots)")
	clientCrt = flag.String("client-cert", "", "Client certificate PEM for servers that require mTLS")
	clientKey = flag.String("client-key", "", "Client private key PEM for --client-cert")
)

func main() {
	flag.Parse()

	if *jwtToken == "" {
		*jwtToken = os.Getenv("WARMOR_TOKEN")
	}

	tlsCfg, err := loadTLSConfig(*caCert, *clientCrt, *clientKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	apiTLSConfig = tlsCfg

	p := tea.NewProgram(
		newApp(*serverURL, *jwtToken),
		tea.WithAltScreen(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
