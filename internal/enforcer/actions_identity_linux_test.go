//go:build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/unix"
)

// Synthetic PIDs NEVER reach the OS: every operation, including signaling, is
// mocked. Real signal tests below use only isolated, owned child processes.
func fakeProcessOps(calls *[]string) linuxProcessOps {
	return linuxProcessOps{
		eventBootLower: func(stamp uint64) uint64 { return stamp },
		namespace:      func() error { *calls = append(*calls, "namespace"); return nil },
		open: func(pid, flags int) (int, error) {
			*calls = append(*calls, "open")
			if pid != 42 || flags != 0 {
				return -1, fmt.Errorf("unexpected pid/flags %d/%d", pid, flags)
			}
			return 73, nil
		},
		close:      func(int) error { *calls = append(*calls, "close"); return nil },
		now:        func() (uint64, error) { *calls = append(*calls, "now"); return 10_000_000_000, nil },
		startTicks: func(uint32) (uint64, error) { *calls = append(*calls, "start"); return 100, nil },
		clockTicks: func() (uint64, error) { *calls = append(*calls, "hz"); return 100, nil },
		signal: func(fd int, sig unix.Signal, info *unix.Siginfo, flags int) error {
			*calls = append(*calls, "signal")
			if fd != 73 || sig != unix.SIGKILL || info != nil || flags != 0 {
				return fmt.Errorf("invalid signal arguments")
			}
			return nil
		},
	}
}

func TestVerifiedProcessPinsPIDBeforeReadingIdentity(t *testing.T) {
	var calls []string
	attempted, err := terminateLinuxEventProcess(&api.Event{PID: 42, KernelTimestampNS: 2_000_000_000}, fakeProcessOps(&calls))
	if !attempted || err != nil {
		t.Fatalf("termination = %v, %v", attempted, err)
	}
	want := []string{"namespace", "open", "now", "start", "hz", "signal", "close"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("operations = %v, want %v", calls, want)
	}
}

func TestVerifiedProcessRefusesUnverifiableIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pid    uint32
		stamp  uint64
		change func(*linuxProcessOps)
	}{
		{name: "missing timestamp", pid: 42},
		{name: "zero PID", stamp: 2_000_000_000},
		{name: "init PID", pid: 1, stamp: 2_000_000_000},
		{name: "negative numeric PID", pid: math.MaxUint32, stamp: 2_000_000_000},
		{name: "future clock", pid: 42, stamp: 11_000_000_000},
		{name: "stale event", pid: 42, stamp: 999_999_999},
		{name: "same tick", pid: 42, stamp: 1_005_000_000},
		{name: "tick upper boundary", pid: 42, stamp: 1_010_000_000},
		{name: "nested PID namespace", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) {
			o.namespace = func() error { return verifyPIDNamespace(initialPIDNamespaceInode+1, "42", 42) }
		}},
		{name: "wrong procfs namespace", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) {
			o.namespace = func() error { return verifyPIDNamespace(initialPIDNamespaceInode, "42000", 42) }
		}},
		{name: "wrong time namespace", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) {
			o.namespace = func() error { return verifyTimeNamespaceOffsets("monotonic -1 0\nboottime 0 0") }
		}},
		{name: "unsupported pidfd", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) { o.open = func(int, int) (int, error) { return -1, unix.ENOSYS } }},
		{name: "pidfd open permission", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) { o.open = func(int, int) (int, error) { return -1, unix.EPERM } }},
		{name: "exited before open", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) { o.open = func(int, int) (int, error) { return -1, unix.ESRCH } }},
		{name: "exited before stat", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) { o.startTicks = func(uint32) (uint64, error) { return 0, unix.ENOENT } }},
		{name: "reused before open or stat", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) { o.startTicks = func(uint32) (uint64, error) { return 201, nil } }},
		{name: "clock unavailable", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) { o.now = func() (uint64, error) { return 0, unix.EIO } }},
		{name: "hz unavailable", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) { o.clockTicks = func() (uint64, error) { return 0, unix.EIO } }},
		{name: "additional suspend uncertainty", pid: 42, stamp: 2_000_000_000, change: func(o *linuxProcessOps) { o.startTicks = func(uint32) (uint64, error) { return 100_000, nil } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			ops := fakeProcessOps(&calls)
			if tc.change != nil {
				tc.change(&ops)
			}
			attempted, err := terminateLinuxEventProcess(&api.Event{PID: tc.pid, KernelTimestampNS: tc.stamp}, ops)
			if attempted || err == nil {
				t.Fatalf("unverified target signaled: %v %v", attempted, err)
			}
			for _, call := range calls {
				if call == "signal" {
					t.Fatal("refused identity reached signal")
				}
			}
		})
	}
}

func TestVerifiedProcessExitedOrReusedAfterStatNeverUsesNumericPID(t *testing.T) {
	for _, signalErr := range []error{unix.ESRCH, unix.EPERM} {
		var calls []string
		ops := fakeProcessOps(&calls)
		ops.signal = func(fd int, _ unix.Signal, _ *unix.Siginfo, _ int) error {
			if fd != 73 {
				t.Fatal("not pinned pidfd")
			}
			return signalErr
		}
		attempted, err := terminateLinuxEventProcess(&api.Event{PID: 42, KernelTimestampNS: 2_000_000_000}, ops)
		if !attempted || !errors.Is(err, signalErr) {
			t.Fatalf("signal failure = %v, %v", attempted, err)
		}
		if calls[len(calls)-1] != "close" {
			t.Fatal("pidfd leaked")
		}
	}
}

func TestProcessStartTickParsing(t *testing.T) {
	valid := "42 (comm ) with\nspaces()) S " + strings.Repeat("0 ", 18) + "12345 0"
	if got, err := parseProcessStartTicks(valid, 42); err != nil || got != 12345 {
		t.Fatalf("start ticks = %d %v", got, err)
	}
	for _, bad := range []string{"", "42 (x) S", strings.Replace(valid, "42 (", "43 (", 1), strings.Replace(valid, "12345", "-1", 1), strings.Replace(valid, "12345", "0", 1)} {
		if _, err := parseProcessStartTicks(bad, 42); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestProcessStartTickBounds(t *testing.T) {
	for _, tc := range []struct{ start, hz, want uint64 }{{100, 100, 1_010_000_000}, {1, 3, 666_666_667}, {99, 100, 1_000_000_000}} {
		if got, err := startTickUpperNS(tc.start, tc.hz); err != nil || got != tc.want {
			t.Fatalf("%+v: %d %v", tc, got, err)
		}
	}
	for _, tc := range []struct{ start, hz uint64 }{{1, 0}, {1, math.MaxUint64}, {math.MaxUint64, 100}, {math.MaxUint64 - 1, 1}} {
		if _, err := startTickUpperNS(tc.start, tc.hz); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}

func TestTimeNamespaceOffsets(t *testing.T) {
	if err := verifyTimeNamespaceOffsets("monotonic 0 0\nboottime 0 0\n"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "monotonic 0 0", "monotonic 0 0\nmonotonic 0 0", "monotonic -1 0\nboottime 0 0", "monotonic 0 0\nboottime 0 1", "monotonic x 0\nboottime 0 0"} {
		if err := verifyTimeNamespaceOffsets(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestPIDNamespaceVerification(t *testing.T) {
	if err := verifyPIDNamespace(initialPIDNamespaceInode, "42", 42); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		inode uint64
		self  string
		own   int
	}{{initialPIDNamespaceInode + 1, "42", 42}, {initialPIDNamespaceInode, "42000", 42}, {initialPIDNamespaceInode, "", 42}} {
		if err := verifyPIDNamespace(tc.inode, tc.self, tc.own); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}

func TestSignalingSuspendBaselineOnlyCorrectsEventsAfterSample(t *testing.T) {
	b := signalingClockBound{monotonic: 100, suspendLower: 1000}
	for _, tc := range []struct{ stamp, want uint64 }{{99, 99}, {100, 1100}, {101, 1101}, {math.MaxUint64, math.MaxUint64}} {
		if got := b.eventBootLower(tc.stamp); got != tc.want {
			t.Fatalf("stamp %d got %d want %d", tc.stamp, got, tc.want)
		}
	}
	if got := (signalingClockBound{}).eventBootLower(99); got != 99 {
		t.Fatal("unavailable baseline corrected timestamp")
	}
}

func TestSuspendCorrectionCannotPromoteStaleEvents(t *testing.T) {
	// Adding an offset sampled AFTER this event would wrongly accept a
	// replacement. Only the raw monotonic lower bound is valid here.
	var calls []string
	ops := fakeProcessOps(&calls)
	ops.eventBootLower = (signalingClockBound{monotonic: 3_000_000_000, suspendLower: 10_000_000_000}).eventBootLower
	ops.startTicks = func(uint32) (uint64, error) { return 500, nil }
	if attempted, err := terminateLinuxEventProcess(&api.Event{PID: 42, KernelTimestampNS: 2_000_000_000}, ops); attempted || err == nil {
		t.Fatalf("stale event promoted: %v %v", attempted, err)
	}
}

func TestClockTicksAuxvParsing(t *testing.T) {
	word := strconv.IntSize / 8
	data := make([]byte, 4*word)
	if word == 8 {
		binary.NativeEndian.PutUint64(data, 17)
		binary.NativeEndian.PutUint64(data[word:], 100)
	} else {
		binary.NativeEndian.PutUint32(data, 17)
		binary.NativeEndian.PutUint32(data[word:], 100)
	}
	if got, err := parseClockTicks(data); err != nil || got != 100 {
		t.Fatalf("%d %v", got, err)
	}
	for _, bad := range [][]byte{nil, {1}, make([]byte, 2*word)} {
		if _, err := parseClockTicks(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestTerminateEventProcess_StaleOrMissingIdentityDoesNotKillChild(t *testing.T) {
	cmd := spawnSleeper(t)
	event := verifiedChildEvent(t, cmd)
	for _, timestamp := range []uint64{0, 1, math.MaxUint64} {
		event.KernelTimestampNS = timestamp
		if attempted, err := terminateEventProcess(event); attempted || err == nil {
			t.Fatalf("invalid timestamp %d: %v %v", timestamp, attempted, err)
		}
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("child unexpectedly exited: %v", err)
		}
	}
}
