//go:build !linux

package worker

import (
	"errors"
	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
)

func applyLimits(protocol.Limits) error { return errors.New("policy-host OS limits unavailable") }
