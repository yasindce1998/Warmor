package main

import (
	"errors"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyhost"
)

// Reject before trust/store bootstrap, outputs, monitors, or child startup. The
// signed daemon owns one agentstore publication; its combined backend commit
// model is not implied by the independent metadata/host APIs.
func checkSignedBackendCombination(signed, atomic, host bool) error {
	if signed && (atomic || host) {
		return errors.New("--signed-assignments with experimental atomic generations or supervised policy host is unsupported until one commit/recovery model is tested")
	}
	return nil
}

func supervisedBackendConfig(enabled bool, path, digest, declarations string, timeout time.Duration) (*policyhost.Config, error) {
	if !enabled {
		if path != "" || digest != "" || declarations != "" {
			return nil, errors.New("policy-host configuration requires --experimental-supervised-policy-host")
		}
		return nil, nil
	}
	if path == "" || digest == "" {
		return nil, errors.New("supervised backend requires --policy-host and --policy-host-sha256")
	}
	c := enforcer.DefaultSupervisedConfig(path, digest, timeout)
	if declarations != "" {
		c.TrustedDeclarationDigests = strings.Split(declarations, ",")
	}
	return &c, nil
}
