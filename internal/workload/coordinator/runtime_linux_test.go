//go:build linux

package coordinator

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type fakeCRI struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	mu               sync.Mutex
	inv              workload.Inventory
	info             string
	statusCalls      int
	changeAfterFirst bool
	fail, block      bool
}

func (s *fakeCRI) ListPodSandbox(ctx context.Context, _ *runtimeapi.ListPodSandboxRequest) (*runtimeapi.ListPodSandboxResponse, error) {
	s.mu.Lock()
	fail, block := s.fail, s.block
	items := s.inv.Sandboxes
	s.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if fail {
		return nil, status.Error(codes.Unavailable, "fake unavailable")
	}
	return &runtimeapi.ListPodSandboxResponse{Items: items}, nil
}
func (s *fakeCRI) ListContainers(context.Context, *runtimeapi.ListContainersRequest) (*runtimeapi.ListContainersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &runtimeapi.ListContainersResponse{Containers: s.inv.Containers}, nil
}
func (s *fakeCRI) ContainerStatus(_ context.Context, req *runtimeapi.ContainerStatusRequest) (*runtimeapi.ContainerStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.inv.Containers[0]
	s.statusCalls++
	if s.changeAfterFirst && s.statusCalls > 1 {
		return nil, status.Error(codes.NotFound, "exited")
	}
	if req.ContainerId != c.Id || !req.Verbose {
		return nil, status.Error(codes.InvalidArgument, "bad status request")
	}
	return &runtimeapi.ContainerStatusResponse{Status: &runtimeapi.ContainerStatus{Id: c.Id, Metadata: c.Metadata, State: c.State, CreatedAt: c.CreatedAt}, Info: map[string]string{"info": s.info}}, nil
}

type fakeVerifier struct {
	claims []ProcessClaim
	closed bool
	err    error
}

func (v *fakeVerifier) Verify(_ context.Context, claims []ProcessClaim) ([]workload.Binding, error) {
	v.claims = append([]ProcessClaim(nil), claims...)
	if v.err != nil {
		return nil, v.err
	}
	var out []workload.Binding
	for _, c := range claims {
		out = append(out, workload.Binding{CgroupID: 42, ContainerID: c.ContainerID, Lifetime: "verified-fixture"})
	}
	return out, nil
}
func (v *fakeVerifier) Close() error { v.closed = true; return nil }

func fakeUnixServer(t *testing.T) (string, *fakeCRI, func()) {
	t.Helper()
	// This is a test-owned fake gRPC endpoint, never a host runtime socket.
	dir, err := os.MkdirTemp("/tmp/opencode", "cri-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "cri.sock")
	l, err := net.Listen("unix", name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	_, inv, _ := inputs()
	fake := &fakeCRI{inv: inv, info: `{"pid":123}`}
	server := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(server, fake)
	go func() { _ = server.Serve(l) }()
	stop := func() { server.Stop(); l.Close() }
	t.Cleanup(func() { stop(); os.Remove(name); os.Remove(dir) })
	return name, fake, stop
}

func TestUnixRuntimeAuthorizedLifecycleAndFailureRetirement(t *testing.T) {
	name, server, _ := fakeUnixServer(t)
	v := &fakeVerifier{}
	cfg := DefaultUnixRuntimeConfig(name, uint32(os.Getuid()), TrustedVerboseInfoPID{AssumeLivePIDOwnership: true}, v)
	cfg.RPCTimeout = 100 * time.Millisecond
	r, err := NewUnixRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	inv, b, err := r.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Containers) != 1 || len(b) != 1 || len(v.claims) != 1 || v.claims[0].PID != 123 {
		t.Fatalf("bad poll: %+v %+v", b, v.claims)
	}
	server.mu.Lock()
	server.info = `{"pid":0}`
	server.mu.Unlock()
	_, b, err = r.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 || len(v.claims) != 0 {
		t.Fatal("invalid PID retained prior binding")
	}
	server.mu.Lock()
	server.fail = true
	server.mu.Unlock()
	if _, _, err = r.Poll(context.Background()); err == nil || r.conn != nil {
		t.Fatal("failed connection retained")
	}
	server.mu.Lock()
	server.fail = false
	server.info = `{"pid":123}`
	server.mu.Unlock()
	if _, _, err = r.Poll(context.Background()); err != nil {
		t.Fatal("reconnect:", err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if !v.closed {
		t.Fatal("verifier not closed")
	}
	if _, _, err = r.Poll(context.Background()); err == nil {
		t.Fatal("poll after close")
	}
}

func TestUnixRuntimeDeadlinesAuthorizationAndBudgets(t *testing.T) {
	name, server, _ := fakeUnixServer(t)
	for _, mode := range []string{"owner", "permissions", "symlink", "deadline", "budget", "message", "verifier"} {
		t.Run(mode, func(t *testing.T) {
			v := &fakeVerifier{}
			cfg := DefaultUnixRuntimeConfig(name, uint32(os.Getuid()), TrustedVerboseInfoPID{AssumeLivePIDOwnership: true}, v)
			cfg.RPCTimeout = 25 * time.Millisecond
			server.mu.Lock()
			server.block = false
			server.inv.Containers = server.inv.Containers[:1]
			server.mu.Unlock()
			switch mode {
			case "owner":
				cfg.SocketUID++
			case "permissions":
				if err := os.Chmod(name, 0602); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(name, 0600)
			case "symlink":
				link := filepath.Join(filepath.Dir(name), "link.sock")
				if err := os.Symlink(name, link); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(link)
				cfg.SocketPath = link
			case "deadline":
				server.mu.Lock()
				server.block = true
				server.mu.Unlock()
			case "budget":
				cfg.MaxContainers = 1
				server.mu.Lock()
				server.inv.Containers = append(server.inv.Containers, server.inv.Containers[0])
				server.mu.Unlock()
			case "message":
				cfg.MaxMessageBytes = 1024
				server.mu.Lock()
				server.info = `{"pid":123,"padding":"` + string(make([]byte, 2048)) + `"}`
				server.mu.Unlock()
			case "verifier":
				v.err = errors.New("bad host mounts")
			}
			r, err := NewUnixRuntime(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			_, b, err := r.Poll(ctx)
			if mode == "message" {
				if len(b) != 0 {
					t.Fatal("oversized status binding accepted")
				}
			} else if err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
	if _, err := NewUnixRuntime(UnixRuntimeConfig{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestVerbosePIDRejectsMissingOrMalformedContract(t *testing.T) {
	name, server, _ := fakeUnixServer(t)
	v := &fakeVerifier{}
	cfg := DefaultUnixRuntimeConfig(name, uint32(os.Getuid()), TrustedVerboseInfoPID{AssumeLivePIDOwnership: true}, v)
	r, err := NewUnixRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, info := range []string{"", `{}`, `{"pid":"123"}`, `{"pid":1}`, `{"pid":-1}`, `{"pid":1.2}`, `{"pid":2147483648}`, `not-json`} {
		server.mu.Lock()
		server.info = info
		server.mu.Unlock()
		_, b, err := r.Poll(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != 0 {
			t.Fatalf("invalid contract accepted: %q", info)
		}
	}
}

func TestVerbosePIDRequiresExplicitTrust(t *testing.T) {
	if _, err := (TrustedVerboseInfoPID{}).PID(context.Background(), nil, nil); err == nil {
		t.Fatal("implicit runtime PID ownership trust")
	}
}

func TestUnixRuntimeRechecksClaimAndRetiresOutageContinuity(t *testing.T) {
	name, server, _ := fakeUnixServer(t)
	host, _, _ := fixtureHost(t)
	r, err := NewUnixRuntime(DefaultUnixRuntimeConfig(name, uint32(os.Getuid()), TrustedVerboseInfoPID{AssumeLivePIDOwnership: true}, host))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, first, err := r.Poll(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatal(first, err)
	}
	server.mu.Lock()
	server.fail = true
	server.mu.Unlock()
	if _, _, err := r.Poll(context.Background()); err == nil {
		t.Fatal("failed poll accepted")
	}
	if len(host.active) != 0 {
		t.Fatal("outage retained evidence")
	}
	server.mu.Lock()
	server.fail = false
	server.mu.Unlock()
	_, next, err := r.Poll(context.Background())
	if err != nil || len(next) != 1 || next[0].Lifetime == first[0].Lifetime {
		t.Fatal("reconnection retained lifetime", err)
	}
	server.mu.Lock()
	server.statusCalls = 0
	server.changeAfterFirst = true
	server.mu.Unlock()
	if _, b, err := r.Poll(context.Background()); err == nil || len(b) != 0 || len(host.active) != 0 {
		t.Fatal("changed PID status retained binding")
	}
}
