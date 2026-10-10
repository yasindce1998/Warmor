package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yasindce1998/warmor/internal/integrity"
)

var version = "dev"

func main() {
	rootfs := flag.String("rootfs", "", "Path to container rootfs to scan")
	output := flag.String("o", "integrity-db.json", "Output database file")
	verify := flag.String("verify", "", "Verify against existing database")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-integrity-scan [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Scan container rootfs and build binary integrity allowlist.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-integrity-scan --rootfs /var/lib/containers/overlay/merged -o db.json\n")
		fmt.Fprintf(os.Stderr, "  warmor-integrity-scan --verify db.json --rootfs /var/lib/containers/overlay/merged\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("warmor-integrity-scan %s\n", version)
		os.Exit(0)
	}

	if *verify != "" {
		runVerify(*verify, *rootfs)
		return
	}

	if *rootfs == "" {
		fmt.Fprintf(os.Stderr, "error: --rootfs is required\n")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Scanning %s...\n", *rootfs)
	db, err := integrity.ScanRootFS(*rootfs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Found %d executables\n", len(db.Binaries))

	if err := db.Save(*output); err != nil {
		fmt.Fprintf(os.Stderr, "error writing database: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Database written to %s\n", *output)
}

func runVerify(dbPath, rootfs string) {
	db, err := integrity.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading database: %v\n", err)
		os.Exit(1)
	}

	if rootfs == "" {
		rootfs = db.RootFS
	}
	if rootfs == "" {
		fmt.Fprintf(os.Stderr, "error: --rootfs required for verification\n")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Verifying %d binaries against %s...\n", len(db.Binaries), rootfs)

	var passed, failed, missing int
	for path := range db.Binaries {
		// Database keys are rootfs-relative (see integrity.ScanRootFS).
		ok, err := db.VerifyInRoot(rootfs, path)
		if err != nil {
			missing++
			fmt.Printf("MISSING  %s (%v)\n", path, err)
			continue
		}
		if ok {
			passed++
		} else {
			failed++
			fmt.Printf("FAIL     %s\n", path)
		}
	}

	fmt.Fprintf(os.Stderr, "\nResults: %d passed, %d failed, %d missing\n", passed, failed, missing)
	if failed > 0 || missing > 0 {
		os.Exit(1)
	}
}
