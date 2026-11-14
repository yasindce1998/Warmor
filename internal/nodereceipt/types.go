// Package nodereceipt implements authenticated, fresh node self-reports. A
// compromised node can lie about its own activation: this is NOT attestation.
package nodereceipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const ManifestDataKey = "activation-manifest.json"

// Posture describes actual local mode, not a promise that every operation is
// blocked. DefaultDenyRequested does not assert policy eligibility or coverage.
type Posture struct {
	Audit                bool `json:"audit"`
	Learning             bool `json:"learning"`
	LSMEnforcement       bool `json:"lsmEnforcement"`
	DefaultDenyRequested bool `json:"defaultDenyRequested"`
}

type Source struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}

// Manifest is committed atomically alongside the artifact and accepted source
// snapshot. Its ID binds exact accepted generations even when bytes are equal.
type Manifest struct {
	Version        int      `json:"version"`
	Revision       string   `json:"revision"`
	Digest         string   `json:"digest"`
	SnapshotDigest string   `json:"snapshotDigest"`
	Compiler       string   `json:"compiler"`
	ABI            uint32   `json:"abi"`
	Posture        Posture  `json:"posture"`
	Sources        []Source `json:"sources"`
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (m Manifest) ID() string {
	b, _ := json.Marshal(m)
	return Digest(b)
}

func (m Manifest) Validate() error {
	validDigest := func(s string) bool {
		b, err := hex.DecodeString(s)
		return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
	}
	if m.Version != 1 || m.Revision == "" || m.Compiler == "" || !validDigest(m.Digest) || !validDigest(m.SnapshotDigest) || len(m.Sources) == 0 || m.ABI == 0 {
		return fmt.Errorf("no eligible desired manifest")
	}
	seen := map[string]bool{}
	for _, s := range m.Sources {
		if s.Namespace == "" || s.Name == "" || s.UID == "" || s.Generation <= 0 || seen[s.UID] {
			return fmt.Errorf("invalid accepted source identity")
		}
		seen[s.UID] = true
	}
	return nil
}

type Registration struct {
	BootEpoch string `json:"bootEpoch"` // new random value per daemon process
}

type Challenge struct {
	Nonce     string    `json:"nonce"`
	BootEpoch string    `json:"bootEpoch"`
	ExpiresAt time.Time `json:"expiresAt"`
	Manifest  Manifest  `json:"manifest"`
}

// Activation is captured from the active evaluator, not a downloaded/prepared
// candidate or a second read of the policy pathname.
type Activation struct {
	Digest      string    `json:"digest"`
	ABI         uint32    `json:"abi"`
	Posture     Posture   `json:"posture"`
	ActivatedAt time.Time `json:"activatedAt"`
}

type Receipt struct {
	Challenge  string     `json:"challenge"`
	BootEpoch  string     `json:"bootEpoch"`
	Sequence   uint64     `json:"sequence"`
	MeasuredAt time.Time  `json:"measuredAt"`
	Manifest   Manifest   `json:"manifest"`
	Active     Activation `json:"active"`
}

type Result struct {
	Required  int
	Applied   int
	All       bool
	Oldest    time.Time
	ExpiresAt time.Time
}
