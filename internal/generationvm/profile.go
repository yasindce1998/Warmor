//go:build linux && integration && generation_daemon_vm

package generationvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/yasindce1998/warmor/pkg/api"
)

// This file is absent from release binaries. Even this profile refuses to arm
// without vimto's actual init and private devices; an environment opt-in alone
// never authorizes host enforcement or fault injection.
var profile struct {
	sync.Mutex
	dir      string
	active   uint64
	attempts map[string]int
}

type control struct {
	HoldID      uint64
	HoldPath    string
	FailDurable bool
	FailDrain   bool
}

func ValidateGuard(initExe string, ports []string) error {
	if filepath.Base(initExe) != "vimto" {
		return errors.New("generation daemon profile requires vimto PID 1")
	}
	seen := map[string]bool{}
	for _, port := range ports {
		seen[strings.TrimSpace(port)] = true
	}
	if !seen["ctrl"] || !seen["stdio"] {
		return errors.New("generation daemon profile requires private vimto ports")
	}
	return nil
}

func Init(dir string) error {
	initExe, err := os.Readlink("/proc/1/exe")
	if err != nil {
		return err
	}
	paths, err := filepath.Glob("/sys/class/virtio-ports/*/name")
	if err != nil {
		return err
	}
	var ports []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		ports = append(ports, string(data))
	}
	if err := ValidateGuard(initExe, ports); err != nil {
		return err
	}
	if !filepath.IsAbs(dir) || !strings.HasPrefix(filepath.Clean(dir), "/var/tmp/warmor-generation-") {
		return errors.New("profile control must be a VM-local /var/tmp/warmor-generation-* directory")
	}
	profile.Lock()
	defer profile.Unlock()
	if profile.dir != "" {
		return errors.New("generation profile already initialized")
	}
	profile.dir, profile.attempts = dir, map[string]int{}
	return writeStatusLocked("profile-ready", 0, nil)
}

func readControlLocked() (control, error) {
	var c control
	data, err := os.ReadFile(filepath.Join(profile.dir, "control.json"))
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(data, &c)
	return c, err
}

func writeStatusLocked(stage string, id uint64, event *api.Event) error {
	key := fmt.Sprintf("%s-%d", stage, id)
	profile.attempts[key]++
	// Same guest CLOCK_MONOTONIC as the fixture's HTTP ingress clock. Sample
	// at this checkpoint, never from control input or a heartbeat claim, and
	// publish the timestamp atomically with the phase record below.
	var stamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp); err != nil {
		return err
	}
	data, err := json.Marshal(struct {
		Stage       string
		Generation  uint64
		Attempt     int
		MonotonicNS int64
		Event       *api.Event `json:",omitempty"`
	}{stage, id, profile.attempts[key], stamp.Nano(), event})
	if err != nil {
		return err
	}
	tmp := filepath.Join(profile.dir, key+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(profile.dir, key+".json"))
}

func Checkpoint(ctx context.Context, stage string, id uint64, event *api.Event) error {
	profile.Lock()
	if profile.dir == "" {
		profile.Unlock()
		return nil
	}
	if stage == "live" {
		profile.active = id
	}
	if id == 0 && stage != "retired" {
		id = profile.active
	}
	c, err := readControlLocked()
	if err != nil {
		profile.Unlock()
		return err
	}
	hold := stage == "event" && event != nil && event.LSMEvent && event.Hook == "exec" && c.HoldID == id && c.HoldPath == event.Filename
	if stage == "event" && !hold {
		profile.Unlock()
		return nil
	}
	err = writeStatusLocked(stage, id, event)
	profile.Unlock()
	if err != nil {
		return err
	}
	if stage == "durable-sync" && c.FailDurable {
		return errors.New("generation VM injected durable-sync failure AFTER live commit")
	}
	if stage == "before-drain" && c.FailDrain {
		return errors.New("generation VM injected pending drain AFTER live commit")
	}
	if !hold {
		return nil
	}
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			profile.Lock()
			c, err = readControlLocked()
			profile.Unlock()
			if err != nil {
				return err
			}
			if c.HoldID != id {
				return nil
			}
		}
	}
}

type evidence struct {
	Phase                                    string
	Generation                               *uint64
	KernelGeneration                         uint64
	LSM                                      bool
	Hook                                     string
	PID, UID                                 uint32
	CgroupID                                 uint64
	Filename                                 string
	Decision                                 string `json:",omitempty"`
	Audit, KernelDenied, Enforced, Attempted bool
}

func record(phase string, event *api.Event, result *api.ActionResult) {
	if event == nil || event.GetType() != api.EventTypeProcess || !strings.HasPrefix(event.Filename, "/var/tmp/warmor-outcome-fixtures/") {
		return
	}
	profile.Lock()
	defer profile.Unlock()
	if profile.dir == "" {
		return
	}
	r := evidence{Phase: phase, KernelGeneration: event.PolicyGeneration, LSM: event.LSMEvent, Hook: event.Hook,
		PID: event.PID, UID: event.UID, CgroupID: event.CgroupID, Filename: event.Filename, KernelDenied: event.KernelDenied}
	if event.GenerationContext != nil {
		id := event.GenerationContext.ID
		r.Generation = &id
	}
	if result != nil {
		r.Decision, r.Audit, r.Enforced, r.Attempted = result.Action.String(), result.Audit, result.Enforced, result.EnforcementAttempted
	}
	file, err := os.OpenFile(filepath.Join(profile.dir, "evidence.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		err = json.NewEncoder(file).Encode(r)
		err = errors.Join(err, file.Close())
	}
	if err != nil {
		_ = os.WriteFile(filepath.Join(profile.dir, "instrumentation-error.txt"), []byte(err.Error()), 0600)
	}
}

func Capture(event *api.Event)                           { record("capture", event, nil) }
func Observe(event *api.Event, result *api.ActionResult) { record("decision", event, result) }
