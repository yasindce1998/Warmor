//go:build !linux || !integration || !generation_daemon_vm

// Package generationvm supplies named, compile-profile-only VM test seams.
// Normal builds cannot configure a seam, pause work, or inject a failure.
package generationvm

import (
	"context"

	"github.com/yasindce1998/warmor/pkg/api"
)

func Checkpoint(context.Context, string, uint64, *api.Event) error { return nil }
func Capture(*api.Event)                                           {}
func Observe(*api.Event, *api.ActionResult)                        {}
