package main

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/yasindce1998/warmor/internal/integrity"
)

// loadIntegrityDigests validates the --integrity-mode/--integrity-db pair and
// returns the allowlist: the distinct SHA-256 digests in the database.
//
// Both flags must be given together. A mode without a database would enforce
// an empty allowlist and refuse every exec on the host, and a database without
// a mode would silently do nothing; either is a misconfiguration.
func loadIntegrityDigests(mode, dbPath string) ([]string, error) {
	switch mode {
	case "", "off":
		if dbPath != "" {
			return nil, fmt.Errorf("--integrity-db given but --integrity-mode is off; set --integrity-mode=audit or enforce")
		}
		return nil, nil
	case "audit", "enforce":
	default:
		return nil, fmt.Errorf("invalid --integrity-mode %q (valid: off, audit, enforce)", mode)
	}
	if dbPath == "" {
		return nil, fmt.Errorf("--integrity-mode=%s requires --integrity-db (build one with warmor-integrity-scan)", mode)
	}

	db, err := integrity.LoadDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("integrity database %s: %w", dbPath, err)
	}

	seen := make(map[string]struct{}, len(db.Binaries))
	for path, b := range db.Binaries {
		if b == nil {
			return nil, fmt.Errorf("integrity database %s: entry %s has no hash", dbPath, path)
		}
		raw, err := hex.DecodeString(b.SHA256)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("integrity database %s: entry %s has invalid sha256 %q", dbPath, path, b.SHA256)
		}
		seen[hex.EncodeToString(raw)] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("integrity database %s is empty; enforcing it would refuse every exec", dbPath)
	}

	digests := make([]string, 0, len(seen))
	for d := range seen {
		digests = append(digests, d)
	}
	sort.Strings(digests)
	return digests, nil
}
