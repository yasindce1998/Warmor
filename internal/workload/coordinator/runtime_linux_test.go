//go:build linux

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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
		if c.ExclusiveCgroupOwnership {
			out = append(out, workload.Binding{CgroupID: 42, ContainerID: c.ContainerID, Lifetime: "verified-fixture"})
		}
	}
	return out, nil
}
func (v *fakeVerifier) Close() error { v.closed = true; return nil }

func fakeUnixServer(t *testing.T) (string, *fakeCRI, func()) {
	t.Helper()
	// This is a test-owned fake gRPC endpoint, never a host runtime socket.
	dir := t.TempDir()
	name := filepath.Join(dir, "cri.sock")
	if len(name) > 100 {
		// Linux sockaddr_un has a short path budget. Keep the physical fixture
		// in t.TempDir but address it through a pinned directory descriptor;
		// long TMPDIR/test names need no harness-specific directory or skip.
		root, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeFixture(t, root) })
		name = filepath.Join("/proc/self/fd", fmt.Sprint(root.Fd()), "cri.sock")
	}
	l, err := net.Listen("unix", name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0600); err != nil {
		closeFixture(t, l)
		t.Fatal(err)
	}
	_, inv, _ := inputs()
	fake := &fakeCRI{inv: inv, info: `{"pid":123}`}
	server := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(server, fake)
	done := make(chan error, 1)
	go func() { done <- server.Serve(l) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			server.Stop()
			if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
			if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				t.Error(err)
			}
		})
	}
	t.Cleanup(stop)
	return name, fake, stop
}

func closeFixture(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil {
		t.Error(err)
	}
}

func TestFakeUnixServerWithLongTempRoot(t *testing.T) {
	// Exercise the sockaddr_un fallback regardless of the CI runner's TMPDIR.
	longRoot := filepath.Join(t.TempDir(), strings.Repeat("fixture-", 16))
	if err := os.Mkdir(longRoot, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", longRoot)
	t.Run("short-address", func(t *testing.T) {
		name, _, stop := fakeUnixServer(t)
		if len(name) > 100 || !strings.HasPrefix(name, "/proc/self/fd/") {
			t.Fatal("long test temp root did not use a short pinned-directory address")
		}
		conn, err := net.Dial("unix", name)
		if err != nil {
			t.Fatal(err)
		}
		closeFixture(t, conn)
		stop()
	})
	t.Run("authorization-and-permissions", TestUnixRuntimeDeadlinesAuthorizationAndBudgets)
}

func TestUnixRuntimeAuthorizedLifecycleAndFailureRetirement(t *testing.T) {
	name, server, _ := fakeUnixServer(t)
	v := &fakeVerifier{}
	cfg := DefaultUnixRuntimeConfig(name, uint32(os.Getuid()), TrustedVerboseInfoPID{AssumeLivePIDOwnership: true}, v)
	cfg.AssumeExclusiveCgroupOwnership = true
	cfg.RPCTimeout = 100 * time.Millisecond
	r, err := NewUnixRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture(t, r)
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
			cfg.AssumeExclusiveCgroupOwnership = true
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
				defer func() {
					if err := os.Chmod(name, 0600); err != nil {
						t.Error(err)
					}
				}()
			case "symlink":
				link := filepath.Join(filepath.Dir(name), "link.sock")
				if err := os.Symlink(name, link); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Remove(link); err != nil {
						t.Error(err)
					}
				}()
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
			defer closeFixture(t, r)
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
	cfg.AssumeExclusiveCgroupOwnership = true
	r, err := NewUnixRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture(t, r)
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
	cfg := DefaultUnixRuntimeConfig(name, uint32(os.Getuid()), TrustedVerboseInfoPID{AssumeLivePIDOwnership: true}, host)
	cfg.AssumeExclusiveCgroupOwnership = true
	r, err := NewUnixRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture(t, r)
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

type unresolvedSecondPID struct {
	TrustedVerboseInfoPID
	unresolved int
}

func (r *unresolvedSecondPID) PID(ctx context.Context, client runtimeapi.RuntimeServiceClient, c *runtimeapi.Container) (int, error) {
	if c.Id == "unresolved-container" {
		r.unresolved++
		return 0, errors.New("container PID unavailable")
	}
	return r.TrustedVerboseInfoPID.PID(ctx, client, c)
}

func TestSharedCgroupWithUnresolvedContainerRequiresExclusiveOwnership(t *testing.T) {
	name, server, _ := fakeUnixServer(t)
	host, proc, cg := fixtureHost(t)
	// Both containers are already in this cgroup. Runtime A's PID assertion is
	// live and accurate, but B cannot be resolved. This is not a stale-PID race.
	if err := os.MkdirAll(filepath.Join(proc, "124/ns"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(proc, "124/stat"), statFixture(124, "101"))
	writeFixture(t, filepath.Join(proc, "124/cgroup"), "0::/kubepods/container\n")
	writeFixture(t, filepath.Join(cg, "kubepods/container/cgroup.procs"), "123\n124\n")
	for n, kind := range []string{"pid", "cgroup", "mnt"} {
		if err := os.Symlink(fmt.Sprintf("%s:[%d]", kind, n+10), filepath.Join(proc, "124/ns", kind)); err != nil {
			t.Fatal(err)
		}
	}
	server.mu.Lock()
	server.inv.Containers = append(server.inv.Containers, &runtimeapi.Container{
		Id: "unresolved-container", State: runtimeapi.ContainerState_CONTAINER_RUNNING,
		PodSandboxId: "other-sandbox", Metadata: &runtimeapi.ContainerMetadata{Name: "other"},
	})
	server.mu.Unlock()
	resolver := &unresolvedSecondPID{TrustedVerboseInfoPID: TrustedVerboseInfoPID{AssumeLivePIDOwnership: true}}
	cfg := DefaultUnixRuntimeConfig(name, uint32(os.Getuid()), resolver, host)
	if cfg.AssumeExclusiveCgroupOwnership {
		t.Fatal("default configuration assumes exclusive cgroup ownership")
	}
	r, err := NewUnixRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	inv, bindings, err := r.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Containers) != 2 || resolver.unresolved != 1 {
		t.Fatal("fixture did not exercise an unresolved second container")
	}
	if len(bindings) != 0 || len(host.active) != 0 {
		t.Fatal("PID membership alone authorized a shared-cgroup identity")
	}
}
