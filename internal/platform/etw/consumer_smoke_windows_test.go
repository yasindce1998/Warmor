//go:build windows

package etw

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/platform/winutil"
	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

// TestConsumerSmoke runs a real ETW session against the kernel providers.
// It needs Administrator rights, so it only runs when WARMOR_ETW_SMOKE=1
// (set by the Windows CI job).
func TestConsumerSmoke(t *testing.T) {
	if os.Getenv("WARMOR_ETW_SMOKE") != "1" {
		t.Skip("set WARMOR_ETW_SMOKE=1 to run (requires Administrator)")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("WARMOR_ETW_SMOKE=1 but the test is not elevated")
	}

	paths := winutil.NewDevicePathMap(winutil.LoadDriveDevices())
	c, err := NewConsumer(Options{
		SessionName: "WarmorETWSmokeTest",
		Providers:   []Provider{ProviderProcess, ProviderFile, ProviderNetwork},
		Procs:       winutil.NewProcTable(),
		Paths:       paths,
	})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan *api.Event, 65536)
	if err := c.Start(events); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := c.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
		// Stop must be idempotent (the platform calls Stop then Close).
		if err := c.Stop(); err != nil {
			t.Errorf("second Stop: %v", err)
		}
	}()
	for _, p := range []Provider{ProviderProcess, ProviderFile, ProviderNetwork} {
		if !c.Enabled(p) {
			t.Errorf("provider %s not enabled", p)
		}
	}

	// Give the session a moment to start delivering.
	time.Sleep(2 * time.Second)

	// Process: run a child with a recognizable command line.
	cmd := exec.Command("cmd.exe", "/c", "echo", "warmor-smoke")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run child: %v", err)
	}

	// File: create and write a file from a child process (our own PID's
	// file I/O is filtered out on purpose).
	dir := longPath(t, t.TempDir()) // runners' %TEMP% is an 8.3 short path; the kernel reports long ones
	target := filepath.Join(dir, "warmor-smoke.txt")
	if err := exec.Command("cmd.exe", "/c", "echo x > "+target).Run(); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Network: a child connecting to a local listener.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T", ln.Addr())
	}
	port := tcpAddr.Port
	ps := exec.Command("powershell.exe", "-NoProfile", "-Command",
		"(New-Object Net.Sockets.TcpClient).Connect('127.0.0.1', "+strconv.Itoa(port)+")")
	if out, err := ps.CombinedOutput(); err != nil {
		t.Fatalf("connect child: %v: %s", err, out)
	}

	var sawProcess, sawFile, sawNetwork bool
	deadline := time.After(20 * time.Second)
	for !(sawProcess && sawFile && sawNetwork) {
		select {
		case ev := <-events:
			switch ev.GetType() {
			case api.EventTypeProcess:
				if ev.Comm == "cmd.exe" && ev.Process != nil &&
					strings.Contains(strings.Join(ev.Process.Args, " "), "warmor-smoke") {
					if !strings.Contains(ev.Filename, `:\`) {
						t.Errorf("process image not translated to a drive path: %q", ev.Filename)
					}
					sawProcess = true
				}
			case api.EventTypeFile:
				if ev.File != nil && strings.EqualFold(ev.File.Path, target) {
					sawFile = true
				}
			case api.EventTypeNetwork:
				if ev.Network != nil && ev.Network.Operation == "connect" &&
					ev.Network.RemoteAddr == "127.0.0.1" && int(ev.Network.RemotePort) == port {
					if ev.Comm != "powershell.exe" {
						t.Errorf("network event comm = %q, want powershell.exe", ev.Comm)
					}
					sawNetwork = true
				}
			}
		case <-deadline:
			t.Fatalf("timed out: process=%v file=%v network=%v (stats %v)",
				sawProcess, sawFile, sawNetwork, c.Stats())
		}
	}
}

func longPath(t *testing.T, p string) string {
	short, err := windows.UTF16FromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_PATH*4)
	n, err := windows.GetLongPathName(&short[0], &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return p
	}
	return windows.UTF16ToString(buf[:n])
}
