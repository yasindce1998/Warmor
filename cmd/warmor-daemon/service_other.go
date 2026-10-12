//go:build !windows
// +build !windows

package main

func isWindowsService() bool {
	return false
}

func runService(func(stop <-chan struct{})) {}

func handleServiceCommand(_ []string) bool {
	return false
}
