//go:build windows
// +build windows

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "warmor"
const serviceDisplayName = "Warmor Security Enforcer"
const serviceDescription = "WASM-powered workload security enforcement daemon"

// serviceStopTimeout bounds how long a stop request waits for the enforcer
// to drain before the service reports stopped anyway.
const serviceStopTimeout = 20 * time.Second

type warmorService struct {
	run  func(stop <-chan struct{})
	elog *eventlog.Log
}

func (s *warmorService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(stop)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	s.info("service running")

	for {
		select {
		case <-done:
			// The daemon returned on its own: that is a failure for a
			// service, so the SCM recovery actions restart it.
			s.error("enforcer exited unexpectedly")
			return false, 1

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending, WaitHint: uint32(serviceStopTimeout / time.Millisecond)}
				close(stop)
				select {
				case <-done:
					s.info("service stopped")
				case <-time.After(serviceStopTimeout):
					s.error("enforcer did not stop in time")
				}
				return false, 0
			}
		}
	}
}

func (s *warmorService) info(msg string) {
	log.Println("Windows Service: " + msg)
	if s.elog != nil {
		_ = s.elog.Info(1, msg)
	}
}

func (s *warmorService) error(msg string) {
	log.Println("Windows Service: " + msg)
	if s.elog != nil {
		_ = s.elog.Error(1, msg)
	}
}

func isWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

// serviceLogPath is where the daemon logs when run by the SCM, which gives
// services no console.
func serviceLogPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Warmor", "warmor-daemon.log")
}

func runService(run func(stop <-chan struct{})) {
	elog, err := eventlog.Open(serviceName)
	if err != nil {
		elog = nil
	} else {
		defer elog.Close()
	}

	logPath := serviceLogPath()
	if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err == nil {
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
			defer f.Close()
			log.SetOutput(io.MultiWriter(os.Stderr, f))
		}
	}

	if err := svc.Run(serviceName, &warmorService{run: run, elog: elog}); err != nil {
		if elog != nil {
			_ = elog.Error(1, fmt.Sprintf("%s service failed: %v", serviceName, err))
		}
		log.Fatalf("Windows Service run failed: %v", err)
	}
}

const serviceUsage = "Usage: warmor-daemon service install [daemon flags...] | uninstall | start | stop"

func handleServiceCommand(args []string) bool {
	if len(args) < 1 || args[0] != "service" {
		return false
	}

	if len(args) < 2 {
		fmt.Println(serviceUsage)
		os.Exit(1)
	}

	var err error
	switch args[1] {
	case "install":
		err = installService(args[2:])
	case "uninstall":
		err = uninstallService()
	case "start":
		err = startService()
	case "stop":
		err = stopService()
	default:
		fmt.Printf("Unknown service command: %s\n", args[1])
		fmt.Println(serviceUsage)
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("service %s: %v", args[1], err)
	}
	fmt.Printf("Service %s: done\n", args[1])
	return true
}

func installService(daemonArgs []string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("resolve absolute path: %w", err)
	}
	daemonArgs, err = absolutizePathFlags(daemonArgs)
	if err != nil {
		return fmt.Errorf("resolve flag paths: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName:      serviceDisplayName,
		Description:      serviceDescription,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: false,
	}, daemonArgs...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// A security service should come back if it dies.
	recovery := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := s.SetRecoveryActions(recovery, uint32((24 * time.Hour).Seconds())); err != nil {
		log.Printf("warning: could not set recovery actions: %v", err)
	}

	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil && !strings.Contains(err.Error(), "exists") {
		_ = s.Delete()
		return fmt.Errorf("install event log source: %w", err)
	}

	fmt.Printf("Installed %s: %s %s\n", serviceName, exePath, strings.Join(daemonArgs, " "))
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	// Deleting a running service only marks it for deletion; stop it first.
	_ = controlAndWait(s, svc.Stop, svc.Stopped)

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	_ = eventlog.Remove(serviceName)
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	return s.Start()
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	return controlAndWait(s, svc.Stop, svc.Stopped)
}

func controlAndWait(s *mgr.Service, cmd svc.Cmd, want svc.State) error {
	status, err := s.Control(cmd)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(serviceStopTimeout + 10*time.Second)
	for status.State != want {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service state %d", want)
		}
		time.Sleep(300 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}
