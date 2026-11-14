//go:build linux

package coordinator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/workload"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This exercises the concrete adapters together using ONLY test-owned HTTP,
// gRPC and proc fixtures. It is not a node/kernel enforcement test.
func TestConcreteAdaptersCoordinateAndRetireDeletion(t *testing.T) {
	name, _, _ := fakeUnixServer(t)
	host, _, _ := fixtureHost(t)
	runtime, err := NewUnixRuntime(DefaultUnixRuntimeConfig(name, uint32(os.Getuid()), TrustedVerboseInfoPID{AssumeLivePIDOwnership: true}, host))
	if err != nil {
		t.Fatal(err)
	}
	pods, _, _ := inputs()
	pods[0].ResourceVersion = "v1"
	deletePod := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			writeJSON(t, w, corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "list-v1"}, Items: pods})
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-deletePod:
			watchEvent(t, w, "DELETED", pods[0])
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	source, err := NewPodHTTPSource(DefaultPodHTTPConfig(server.URL, "node", server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig("node", "containerd")
	cfg.PollInterval = 20 * time.Millisecond
	c, err := New(cfg, runtime, source)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("concrete adapters did not close")
		}
	}()
	eventually(t, func() bool { return c.Current().Ready() })
	host.mu.Lock()
	var cg uint64
	var lifetime string
	for id, b := range host.active {
		cg = id
		lifetime = b.binding.Lifetime
	}
	host.mu.Unlock()
	view := c.Current()
	if _, reason := view.Lookup(cg, lifetime); reason != workload.Verified {
		t.Fatal("concrete join not verified", reason)
	}
	close(deletePod)
	eventually(t, func() bool {
		_, reason := c.Current().Lookup(cg, lifetime)
		return c.Current().Epoch() > view.Epoch() && reason != workload.Verified
	})
	if _, reason := view.Lookup(cg, lifetime); reason != Unavailable {
		t.Fatal("retained concrete view survived deletion")
	}
}
