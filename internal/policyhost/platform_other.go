//go:build !linux

package policyhost

import (
	"os"
	"os/exec"
)

func supported() error                                   { return ErrUnsupported }
func trustedExecutable(string, string) (*os.File, error) { return nil, ErrUnsupported }
func readRegular(string, int64) ([]byte, error)          { return nil, ErrUnsupported }
func command(*os.File) *exec.Cmd                         { return nil }
func kill(*exec.Cmd)                                     {}
