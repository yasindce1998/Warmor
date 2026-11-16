//go:build !windows

package main

import "log"

// daemonFatalf/daemonFatal keep fatal errors identical on platforms that do
// not have the Windows service lifecycle. Their Windows counterparts also
// write the Application event log and unwind the service goroutine.
func daemonFatalf(format string, args ...any) { log.Fatalf(format, args...) }

func daemonFatal(v ...any) { log.Fatal(v...) }

// No service lifecycle outside Windows.
func signalServiceReady() {}
