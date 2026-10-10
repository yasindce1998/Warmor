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
	"strings"
	"sync"
	"sync/atomic"
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

	// A clean end of stream is not an error.
	if err := m.poll(context.Background()); err != nil {
		t.Fatalf("poll err = %v, want nil at clean end of stream", err)
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

func TestContainerdMonitor_PollNonOKStatus(t *testing.T) {
	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A JSON body must not be decoded as events on an error status.
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(ContainerdEvent{Topic: "/bogus"})
	}))
	calls := 0
	m := NewContainerdMonitor(sock, func(ContainerdEvent) { calls++ }, testLogger())
	err := m.poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("poll err = %v, want unexpected status 503", err)
	}
	if calls != 0 {
		t.Errorf("handler called %d times on error response, want 0", calls)
	}
}

// TestContainerdMonitor_WatchReconnectsOnCleanEOF: a stream that ends
// normally must be re-opened immediately, not treated as an error with a 5s
// backoff during which events would be missed.
func TestContainerdMonitor_WatchReconnectsOnCleanEOF(t *testing.T) {
	var conns atomic.Int32
	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := conns.Add(1)
		_ = json.NewEncoder(w).Encode(ContainerdEvent{Topic: "/tasks/start", Container: fmt.Sprint(n)})
	}))

	received := make(chan string, 16)
	m := NewContainerdMonitor(sock, func(e ContainerdEvent) {
		select {
		case received <- e.Container:
		default:
		}
	}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Watch(ctx) }()

	// Well under the 5s error backoff.
	deadline := time.After(2 * time.Second)
	for _, want := range []string{"1", "2", "3"} {
		select {
		case got := <-received:
			if got != want {
				t.Fatalf("event from connection %s, want %s", got, want)
			}
		case <-deadline:
			t.Fatalf("Watch did not reconnect promptly after clean EOF (connections: %d)", conns.Load())
		}
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Watch err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Watch did not return after cancellation")
	}
}

func TestContainerdMonitor_WatchStopsDuringBackoff(t *testing.T) {
	var conns atomic.Int32
	attempted := make(chan struct{}, 1)
	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conns.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		select {
		case attempted <- struct{}{}:
		default:
		}
	}))

	m := NewContainerdMonitor(sock, func(ContainerdEvent) {}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Watch(ctx) }()

	select {
	case <-attempted:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for first poll")
	}
	// A real error puts Watch into its 5s backoff; cancel must interrupt it.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Watch err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Watch did not return after cancellation")
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("connections = %d, want 1 (error must back off, not retry immediately)", n)
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

	t.Run("error status", func(t *testing.T) {
		sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// A decodable body must not be mistaken for a task list.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"tasks":[{"id":"ghost","status":"RUNNING"}]}`))
		}))
		s := NewShimPlugin(sock, NewPolicyScope(), testLogger())
		tasks, err := s.ListTasks(context.Background(), "default")
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("ListTasks err = %v, want unexpected status 404", err)
		}
		if tasks != nil {
			t.Errorf("tasks = %v, want nil on error", tasks)
		}
	})
}

func TestShimPlugin_ListTasksEscapesNamespace(t *testing.T) {
	var gotNS, gotRaw string
	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNS = r.URL.Query().Get("namespace")
		gotRaw = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"tasks":[]}`))
	}))
	s := NewShimPlugin(sock, NewPolicyScope(), testLogger())
	ns := "a&namespace=evil b\x7f"
	if _, err := s.ListTasks(context.Background(), ns); err != nil {
		t.Fatalf("ListTasks: %v", err)
	}
	if gotNS != ns {
		t.Errorf("server saw namespace %q, want %q (raw query %q)", gotNS, ns, gotRaw)
	}
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

func TestShimPlugin_SyncRunningContainersBindsLabelledPolicy(t *testing.T) {
	root := withHostRoot(t)
	taskDir := filepath.Join(root, "run/containerd/io.containerd.runtime.v2.task", "k8s.io")
	touch(t, filepath.Join(taskDir, "web", "config.json"),
		`{"annotations":{"io.warmor/policy":"web-policy","io.kubernetes.container.image":"nginx:1.25"}}`)
	touch(t, filepath.Join(taskDir, "nolabel", "config.json"), `{"annotations":{"other":"x"}}`)

	sock := newUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("namespace") != "k8s.io" {
			_, _ = w.Write([]byte(`{"tasks":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tasks": []ContainerdTask{
				{ID: "web", PID: 1, Status: "RUNNING"},
				{ID: "nolabel", PID: 2, Status: "RUNNING"},
			},
		})
	}))

	scope := NewPolicyScope()
	s := NewShimPlugin(sock, scope, testLogger())
	if err := s.SyncRunningContainers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, ok := scope.Lookup("web"); !ok || got != "web-policy" {
		t.Errorf("Lookup(web) = %q,%v; want web-policy", got, ok)
	}
	if got, ok := scope.LookupByImage("nginx:1.25"); !ok || got != "web-policy" {
		t.Errorf("LookupByImage = %q,%v; want web-policy", got, ok)
	}
	if got, ok := scope.LookupByNamespace("k8s.io"); !ok || got != "web-policy" {
		t.Errorf("LookupByNamespace = %q,%v; want web-policy", got, ok)
	}
	if n := len(scope.All()); n != 1 {
		t.Errorf("bindings = %d, want 1", n)
	}
}
