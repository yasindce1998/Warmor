package main

import (
	"errors"
	"strings"
	"time"

	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/policyhost"
)

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
