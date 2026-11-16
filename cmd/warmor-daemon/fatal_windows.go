//go:build windows

package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/windows/svc/eventlog"
)

// serviceFatal is the sentinel used to unwind the service goroutine on a
// startup failure. log.Fatalf calls os.Exit directly, which the SCM sees as a
// process exit with no Application event-log entry and no clean Close().
type serviceFatal string

var (
	serviceEventLog  *eventlog.Log
	runningAsService bool
)

func writeServiceEvent(msg string) {
	if serviceEventLog != nil {
		_ = serviceEventLog.Error(1, msg)
	}
}

// daemonFatalf records a fatal startup error in the Application event log and
// aborts. In service mode it panics with serviceFatal so the service handler
// can report the failure to the SCM and let its recovery actions restart us;
// as a console process it exits with status 1 as before.
func daemonFatalf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	writeServiceEvent(msg)
	log.Printf("FATAL: %s", msg)
	if runningAsService {
		panic(serviceFatal(msg))
	}
	os.Exit(1)
}

func daemonFatal(v ...any) {
	daemonFatalf("%s", fmt.Sprint(v...))
}
