//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package compiler

import (
	"errors"
	"os"
)

var errArtifactPlatform = errors.New("safe compiled artifact publication is unsupported on this platform")

// Fail closed where no no-follow open, handle link-count check, and durable
// replacement implementation exists. Rust-only generation remains available.
func openArtifact(string, bool) (*os.File, error) { return nil, errArtifactPlatform }

func checkArtifactLinkCount(*os.File, os.FileInfo) error { return errArtifactPlatform }

func checkArtifactIdentity(string, *os.File, os.FileInfo) error { return errArtifactPlatform }

func replaceArtifact(string, string) (bool, error) { return false, errArtifactPlatform }
