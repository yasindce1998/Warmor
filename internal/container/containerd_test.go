package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newUnixServer starts an HTTP server listening on a unix socket in a short
// temp directory (unix socket paths are limited to ~108 bytes) and returns
// the socket path.
func newUnixServer(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wct")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

// ---- ContainerdMonitor ----

func TestNewContainerdMonitor_DefaultSocket(t *testing.T) {
	m := NewContainerdMonitor("", func(ContainerdEvent) {}, testLogger())
	if m.socketPath != "/run/containerd/containerd.sock" {
		t.Errorf("socketPath = %q, want default", m.socketPath)
	}
	if m.client == nil {
		t.Error("client is nil")
	}

	m = NewContainerdMonitor("/tmp/custom.sock", nil, testLogger())
	if m.socketPath != "/tmp/custom.sock" {
		t.Errorf("socketPath = %q, want custom", m.socketPath)
	}
}

func TestContainerdMonitor_PollDeliversEvents(t *testing.T) {
	want := []ContainerdEvent{
		{Topic: "/tasks/start", Container: "c1", Namespace: "k8s.io", Image: "nginx:1", PID: 10},
		{Topic: "/tasks/exit", Container: "c2", Namespace: "default", PID: 20},
	}
	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			http.NotFound(w, r)
			return
		}
		enc := json.NewEncoder(w)
		for _, e := range want {
			_ = enc.Encode(e)
		}
	}))

	var got []ContainerdEvent
	m := NewContainerdMonitor(sock, func(e ContainerdEvent) { got = append(got, e) }, testLogger())

	err := m.poll(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Fatalf("poll err = %v, want io.EOF at end of stream", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestContainerdMonitor_PollMalformedJSON(t *testing.T) {
	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"topic":"/tasks/start"}` + "\n" + `{not json`))
	}))

	calls := 0
	m := NewContainerdMonitor(sock, func(ContainerdEvent) { calls++ }, testLogger())
	err := m.poll(context.Background())
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("poll err = %v, want JSON syntax error", err)
	}
	if calls != 1 {
		t.Errorf("handler called %d times, want 1", calls)
	}
}

func TestContainerdMonitor_PollDialError(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "missing.sock")
	m := NewContainerdMonitor(sock, func(ContainerdEvent) {}, testLogger())
	if err := m.poll(context.Background()); err == nil {
		t.Fatal("expected dial error for missing socket")
	}
}

func TestContainerdMonitor_WatchCancelledContext(t *testing.T) {
	m := NewContainerdMonitor(filepath.Join(t.TempDir(), "x.sock"), func(ContainerdEvent) {}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Watch(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch err = %v, want context.Canceled", err)
	}
}

func TestContainerdMonitor_WatchStopsDuringBackoff(t *testing.T) {
	var mu sync.Mutex
	var got []string
	received := make(chan struct{}, 1)

	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ContainerdEvent{Topic: "/tasks/start", Container: "abc"})
	}))

	m := NewContainerdMonitor(sock, func(e ContainerdEvent) {
		mu.Lock()
		got = append(got, e.Container)
		mu.Unlock()
		select {
		case received <- struct{}{}:
		default:
		}
	}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Watch(ctx) }()

	select {
	case <-received:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for event")
	}
	// The stream has ended (EOF) so Watch is now in its 5s backoff; cancel
	// must interrupt it promptly.
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Watch err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Watch did not return after cancellation")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 || got[0] != "abc" {
		t.Errorf("got events %v, want [abc]", got)
	}
}

// ---- ShimPlugin ----

func TestNewShimPlugin_DefaultSocket(t *testing.T) {
	s := NewShimPlugin("", NewPolicyScope(), testLogger())
	if s.socketPath != "/run/containerd/containerd.sock" {
		t.Errorf("socketPath = %q, want default", s.socketPath)
	}
	if s.client.Timeout != 10*time.Second {
		t.Errorf("client timeout = %v, want 10s", s.client.Timeout)
	}
}

func TestShimPlugin_ListTasks(t *testing.T) {
	var gotNS []string
	var mu sync.Mutex
	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containerd.services.tasks.v1.Tasks/List" {
			http.NotFound(w, r)
			return
		}
		ns := r.URL.Query().Get("namespace")
		mu.Lock()
		gotNS = append(gotNS, ns)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tasks": []ContainerdTask{
				{ID: "t1-" + ns, PID: 100, Status: "RUNNING", Namespace: ns},
				{ID: "t2-" + ns, PID: 200, Status: "STOPPED", Namespace: ns},
			},
		})
	}))

	s := NewShimPlugin(sock, NewPolicyScope(), testLogger())
	tasks, err := s.ListTasks(context.Background(), "k8s.io")
	if err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("got %d tasks, want 2", len(tasks))
	}
	if tasks[0].ID != "t1-k8s.io" || tasks[0].PID != 100 || tasks[0].Status != "RUNNING" {
		t.Errorf("unexpected task[0]: %+v", tasks[0])
	}
	if len(gotNS) != 1 || gotNS[0] != "k8s.io" {
		t.Errorf("server saw namespaces %v, want [k8s.io]", gotNS)
	}
}

func TestShimPlugin_ListTasksErrors(t *testing.T) {
	t.Run("dial error", func(t *testing.T) {
		s := NewShimPlugin(filepath.Join(t.TempDir(), "missing.sock"), NewPolicyScope(), testLogger())
		if _, err := s.ListTasks(context.Background(), "default"); err == nil {
			t.Fatal("expected error for missing socket")
		}
	})

	t.Run("bad json", func(t *testing.T) {
		sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		s := NewShimPlugin(sock, NewPolicyScope(), testLogger())
		if _, err := s.ListTasks(context.Background(), "default"); err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("bad url", func(t *testing.T) {
		s := NewShimPlugin(filepath.Join(t.TempDir(), "x.sock"), NewPolicyScope(), testLogger())
		// A control character makes the request URL unparsable.
		if _, err := s.ListTasks(context.Background(), "bad\x7fns"); err == nil {
			t.Fatal("expected URL parse error")
		}
	})
}

func TestShimPlugin_SyncRunningContainers(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		mu.Lock()
		seen[ns]++
		mu.Unlock()
		if ns == "default" {
			// One namespace failing must not stop the sync.
			_, _ = w.Write([]byte("garbage"))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tasks": []ContainerdTask{
				{ID: fmt.Sprintf("warmor-test-nonexistent-%d", time.Now().UnixNano()), PID: 1, Status: "RUNNING"},
				{ID: "warmor-test-stopped", PID: 2, Status: "STOPPED"},
			},
		})
	}))

	scope := NewPolicyScope()
	s := NewShimPlugin(sock, scope, testLogger())
	if err := s.SyncRunningContainers(context.Background()); err != nil {
		t.Fatalf("SyncRunningContainers: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen["k8s.io"] != 1 || seen["default"] != 1 {
		t.Errorf("namespaces queried = %v, want k8s.io and default once each", seen)
	}
	// Labels for these fake containers do not exist on disk, so nothing is bound.
	if n := len(scope.All()); n != 0 {
		t.Errorf("expected no bindings, got %d", n)
	}
}

func TestShimPlugin_SyncRunningContainersAllFail(t *testing.T) {
	s := NewShimPlugin(filepath.Join(t.TempDir(), "missing.sock"), NewPolicyScope(), testLogger())
	if err := s.SyncRunningContainers(context.Background()); err != nil {
		t.Errorf("SyncRunningContainers should swallow per-namespace errors, got %v", err)
	}
}
