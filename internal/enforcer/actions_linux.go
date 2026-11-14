//go:build linux

package enforcer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/unix"
)

var errProcessIdentity = errors.New("process identity cannot be verified; termination refused")

// Reserved PROC_PID_INIT_INO from Linux proc_ns.h, not a dynamically allocated
// inode. /proc/1 == /proc/self or NS_GET_PARENT returning EPERM is NOT proof of
// the initial namespace. Unknown namespace layouts are unsupported, not guessed.
const initialPIDNamespaceInode = 0xeffffffc

type linuxProcessOps struct {
	open           func(int, int) (int, error)
	close          func(int) error
	namespace      func() error
	startTicks     func(uint32) (uint64, error)
	clockTicks     func() (uint64, error)
	now            func() (uint64, error)
	eventBootLower func(uint64) uint64
	signal         func(int, unix.Signal, *unix.Siginfo, int) error
}

// Taking BOOTTIME first and MONOTONIC second provides a lower bound on suspend
// accumulated BEFORE the second sample. Only events generated after that sample
// may use it. Adding a current suspend offset to an old queued event is UNSAFE.
type signalingClockBound struct{ monotonic, suspendLower uint64 }

var signalingClockBaseline = sampleSignalingClockBaseline()

func sampleSignalingClockBaseline() signalingClockBound {
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return signalingClockBound{}
	}
	mono, err := monotonicNowNS()
	if err != nil {
		return signalingClockBound{}
	}
	b := signalingClockBound{monotonic: mono}
	if uint64(boot.Nano()) > mono {
		b.suspendLower = uint64(boot.Nano()) - mono
	}
	return b
}

func (b signalingClockBound) eventBootLower(stamp uint64) uint64 {
	if b.monotonic != 0 && stamp >= b.monotonic && stamp <= math.MaxUint64-b.suspendLower {
		return stamp + b.suspendLower
	}
	return stamp
}

func terminateEventProcess(event *api.Event) (bool, error) {
	return terminateLinuxEventProcess(event, linuxProcessOps{
		open: unix.PidfdOpen, close: unix.Close, namespace: verifySignalingNamespaces,
		startTicks: readProcessStartTicks, clockTicks: readClockTicks,
		now: monotonicNowNS, eventBootLower: signalingClockBaseline.eventBootLower,
		signal: unix.PidfdSendSignal,
	})
}

// Pin the process lifetime BEFORE reading /proc. Exit/reuse after acquisition
// cannot redirect the signal. /proc might see a replacement but the pidfd still
// refers to the old lifetime. A replacement before acquisition is rejected by
// its start tick being newer than the event.
//
// /proc starttime is CLOCK_BOOTTIME rounded down to USER_HZ ticks; BPF supplies
// initial CLOCK_MONOTONIC. BOOTTIME >= MONOTONIC. The entire start tick must
// strictly precede a LOWER bound on event BOOTTIME. Use only pre-event suspend
// offsets, never wall time, guessed tolerances, or a post-event suspend offset.
func terminateLinuxEventProcess(event *api.Event, ops linuxProcessOps) (bool, error) {
	if event.PID <= 1 || event.PID > math.MaxInt32 {
		return false, fmt.Errorf("%w: unsafe PID %d", errProcessIdentity, event.PID)
	}
	if event.KernelTimestampNS == 0 {
		return false, fmt.Errorf("%w: missing trusted kernel monotonic timestamp", errProcessIdentity)
	}
	if err := ops.namespace(); err != nil {
		return false, fmt.Errorf("%w: %v", errProcessIdentity, err)
	}
	fd, err := ops.open(int(event.PID), 0)
	if err != nil {
		return false, fmt.Errorf("pidfd_open(%d), no numeric-PID fallback: %w", event.PID, err)
	}
	defer func() { _ = ops.close(fd) }()
	now, err := ops.now()
	if err != nil {
		return false, fmt.Errorf("%w: read monotonic clock: %v", errProcessIdentity, err)
	}
	if event.KernelTimestampNS > now {
		return false, fmt.Errorf("%w: future timestamp or wrong clock domain", errProcessIdentity)
	}
	start, err := ops.startTicks(event.PID)
	if err != nil {
		return false, fmt.Errorf("read process %d start identity: %w", event.PID, err)
	}
	hz, err := ops.clockTicks()
	if err != nil {
		return false, fmt.Errorf("%w: read USER_HZ: %v", errProcessIdentity, err)
	}
	upper, err := startTickUpperNS(start, hz)
	if err != nil {
		return false, err
	}
	if upper >= ops.eventBootLower(event.KernelTimestampNS) {
		return false, fmt.Errorf("%w: process start tick does not strictly precede event (stale/reused PID, tick ambiguity, or suspend uncertainty)", errProcessIdentity)
	}
	if err := ops.signal(fd, unix.SIGKILL, nil, 0); err != nil {
		return true, fmt.Errorf("pidfd_send_signal(%d, SIGKILL): %w", event.PID, err)
	}
	return true, nil
}

func startTickUpperNS(start, hz uint64) (uint64, error) {
	if hz == 0 || hz > 1_000_000_000 || start == math.MaxUint64 {
		return 0, fmt.Errorf("%w: invalid process start tick or USER_HZ", errProcessIdentity)
	}
	// ceil((start+1)*1e9/hz), without overflowing the multiplication.
	ticks := start + 1
	seconds, remainder := ticks/hz, ticks%hz
	fraction := (remainder*1_000_000_000 + hz - 1) / hz
	if seconds > (math.MaxUint64-fraction)/1_000_000_000 {
		return 0, fmt.Errorf("%w: process start time overflow", errProcessIdentity)
	}
	return seconds*1_000_000_000 + fraction, nil
}

func readProcessStartTicks(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	return parseProcessStartTicks(string(data), pid)
}

func parseProcessStartTicks(stat string, pid uint32) (uint64, error) {
	// comm may contain spaces, newlines, and parentheses. The LAST ')' is its
	// delimiter; the remaining numeric fields cannot contain parentheses.
	open, end := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 1 || end <= open || strings.TrimSpace(stat[:open]) != strconv.FormatUint(uint64(pid), 10) {
		return 0, fmt.Errorf("%w: malformed /proc stat PID/comm", errProcessIdentity)
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("%w: missing /proc stat starttime", errProcessIdentity)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64) // field 22
	if err != nil || start == 0 {
		return 0, fmt.Errorf("%w: invalid /proc stat starttime", errProcessIdentity)
	}
	return start, nil
}

func readClockTicks() (uint64, error) {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, err
	}
	return parseClockTicks(data)
}

func parseClockTicks(data []byte) (uint64, error) {
	word := strconv.IntSize / 8
	if len(data)%(2*word) != 0 {
		return 0, fmt.Errorf("malformed auxv")
	}
	read := func(b []byte) uint64 {
		if word == 4 {
			return uint64(binary.NativeEndian.Uint32(b))
		}
		return binary.NativeEndian.Uint64(b)
	}
	for len(data) >= 2*word {
		tag, value := read(data), read(data[word:])
		if tag == 0 {
			break
		} // AT_NULL
		if tag == 17 && value > 0 && value <= 1_000_000_000 {
			return value, nil
		} // AT_CLKTCK
		data = data[2*word:]
	}
	return 0, fmt.Errorf("AT_CLKTCK unavailable")
}

func monotonicNowNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func verifySignalingNamespaces() error {
	var fs unix.Statfs_t
	if err := unix.Statfs("/proc", &fs); err != nil {
		return err
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return fmt.Errorf("/proc is not procfs")
	}
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &ns); err != nil {
		return err
	}
	self, err := os.Readlink("/proc/self")
	if err != nil {
		return err
	}
	if err := verifyPIDNamespace(ns.Ino, self, os.Getpid()); err != nil {
		return err
	}
	data, err := os.ReadFile("/proc/self/timens_offsets")
	if err != nil {
		return fmt.Errorf("cannot verify initial clock domain: %w", err)
	}
	return verifyTimeNamespaceOffsets(string(data))
}

func verifyPIDNamespace(inode uint64, procSelf string, ownPID int) error {
	if inode != initialPIDNamespaceInode {
		return fmt.Errorf("initial PID namespace required for host-PID kernel events (use hostPID)")
	}
	if procSelf != strconv.Itoa(ownPID) {
		return fmt.Errorf("procfs PID namespace does not match daemon")
	}
	return nil
}

func verifyTimeNamespaceOffsets(data string) error {
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || (fields[0] != "monotonic" && fields[0] != "boottime") || seen[fields[0]] {
			return fmt.Errorf("cannot verify time namespace offsets")
		}
		sec, errSec := strconv.ParseInt(fields[1], 10, 64)
		ns, errNS := strconv.ParseInt(fields[2], 10, 64)
		if errSec != nil || errNS != nil || sec != 0 || ns != 0 {
			return fmt.Errorf("nonzero or invalid time namespace offset")
		}
		seen[fields[0]] = true
	}
	if !seen["monotonic"] || !seen["boottime"] {
		return fmt.Errorf("missing time namespace offset")
	}
	return nil
}
