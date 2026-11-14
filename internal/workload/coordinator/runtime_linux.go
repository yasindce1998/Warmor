//go:build linux

package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/workload"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// PIDResolver is an explicitly trusted, runtime-specific assertion of the live
// init PID belonging to this exact running container, including protection
// against stale runtime responses and PID reuse. CRI v1 has no such guarantee.
// Never implement this by scanning process names, cgroup names, or ID prefixes.
type PIDResolver interface {
	PID(context.Context, runtimeapi.RuntimeServiceClient, *runtimeapi.Container) (int, error)
}

// TrustedVerboseInfoPID opts into the runtime-specific Info["info"].pid contract.
// Use only after validating that contract for the installed runtime/version.
// A compromised runtime can lie about PID ownership; proc checks cannot repair
// this trust boundary. This is NOT a portable CRI PID discovery API.
type TrustedVerboseInfoPID struct {
	// Required opt-in: the installed runtime must guarantee the live PID's
	// ownership during verification, not merely return a cached integer. If
	// this cannot be established, leave false and identities stay unknown.
	AssumeLivePIDOwnership bool
}

func (resolver TrustedVerboseInfoPID) PID(ctx context.Context, client runtimeapi.RuntimeServiceClient, c *runtimeapi.Container) (int, error) {
	if !resolver.AssumeLivePIDOwnership {
		return 0, errors.New("runtime live PID ownership contract not authorized")
	}
	if client == nil || c == nil || !safeID(c.Id) {
		return 0, errors.New("missing exact runtime container claim")
	}
	r, err := client.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{ContainerId: c.Id, Verbose: true})
	if err != nil {
		return 0, err
	}
	if r == nil || r.Status == nil || r.Status.Id != c.Id || r.Status.State != runtimeapi.ContainerState_CONTAINER_RUNNING ||
		r.Status.CreatedAt != c.CreatedAt || r.Status.Metadata == nil || c.Metadata == nil ||
		r.Status.Metadata.Name != c.Metadata.Name || r.Status.Metadata.Attempt != c.Metadata.Attempt {
		return 0, errors.New("runtime PID status does not corroborate inventory")
	}
	info := r.Info["info"]
	if len(info) == 0 || len(info) > 64<<10 {
		return 0, errors.New("runtime PID info budget exceeded or missing")
	}
	var value struct {
		PID json.RawMessage `json:"pid"`
	}
	if err := json.Unmarshal([]byte(info), &value); err != nil {
		return 0, err
	}
	// encoding/json.Number also accepts a quoted number; the runtime contract
	// here requires an actual integer JSON token, with no coercion.
	pid, err := strconv.ParseInt(string(value.PID), 10, 32)
	if err != nil || pid <= 1 {
		return 0, errors.New("invalid runtime init PID")
	}
	return int(pid), nil
}

type BindingVerifier interface {
	// Verify replaces the complete previous evidence set, retiring absent or
	// unprovable containers. Individual failures must not retain old bindings.
	Verify(context.Context, []ProcessClaim) ([]workload.Binding, error)
	Close() error
}

type ProcessClaim struct {
	ContainerID string
	PID         int
}

type UnixRuntimeConfig struct {
	SocketPath                                   string // explicit absolute allowlisted endpoint; no autodiscovery
	SocketUID                                    uint32 // both filesystem owner and connected SO_PEERCRED UID
	ConnectTimeout, RPCTimeout, PollTimeout      time.Duration
	MaxMessageBytes, MaxContainers, MaxSandboxes int
	Resolver                                     PIDResolver
	Verifier                                     BindingVerifier
}

func DefaultUnixRuntimeConfig(path string, uid uint32, resolver PIDResolver, verifier BindingVerifier) UnixRuntimeConfig {
	return UnixRuntimeConfig{SocketPath: path, SocketUID: uid, ConnectTimeout: 3 * time.Second, RPCTimeout: 5 * time.Second, PollTimeout: 10 * time.Second,
		MaxMessageBytes: 16 << 20, MaxContainers: 8192, MaxSandboxes: 4096, Resolver: resolver, Verifier: verifier}
}

type UnixRuntime struct {
	cfg    UnixRuntimeConfig
	mu     sync.Mutex
	conn   *grpc.ClientConn
	closed bool
}

func NewUnixRuntime(cfg UnixRuntimeConfig) (*UnixRuntime, error) {
	if !filepath.IsAbs(cfg.SocketPath) || filepath.Clean(cfg.SocketPath) != cfg.SocketPath || len(cfg.SocketPath) > 100 ||
		cfg.ConnectTimeout < time.Millisecond || cfg.ConnectTimeout > time.Minute || cfg.RPCTimeout < time.Millisecond || cfg.RPCTimeout > time.Minute ||
		cfg.PollTimeout < time.Millisecond || cfg.PollTimeout > time.Minute ||
		cfg.MaxMessageBytes < 1024 || cfg.MaxMessageBytes > 64<<20 || cfg.MaxContainers < 1 || cfg.MaxContainers > 65536 ||
		cfg.MaxSandboxes < 1 || cfg.MaxSandboxes > 65536 || cfg.Resolver == nil || cfg.Verifier == nil {
		return nil, errors.New("invalid authorized Unix runtime configuration")
	}
	return &UnixRuntime{cfg: cfg}, nil
}

func (r *UnixRuntime) dial(ctx context.Context) (net.Conn, error) {
	info, err := os.Lstat(r.cfg.SocketPath)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(r.cfg.SocketPath, &stat); err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 || stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != r.cfg.SocketUID || stat.Mode&0002 != 0 {
		return nil, errors.New("unauthorized runtime socket type, owner, or world-write permission")
	}
	dialer := net.Dialer{Timeout: r.cfg.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "unix", r.cfg.SocketPath)
	if err != nil {
		return nil, err
	}
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, errors.New("runtime connection is not Unix")
	}
	raw, err := uconn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, err
	}
	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || credErr != nil || cred == nil || cred.Uid != r.cfg.SocketUID {
		conn.Close()
		return nil, errors.New("runtime socket peer is not authorized")
	}
	return conn, nil
}

// Poll serializes calls, bounds every RPC, checks CRI v1 availability with real
// inventory methods, and drops failed connections. gRPC reconnect attempts use
// bounded backoff and repeat endpoint/peer authorization on every dial.
func (r *UnixRuntime) Poll(ctx context.Context) (inv workload.Inventory, bindings []workload.Binding, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return inv, nil, errors.New("runtime closed")
	}
	ctx, cancelPoll := context.WithTimeout(ctx, r.cfg.PollTimeout)
	defer cancelPoll()
	if r.conn == nil {
		r.conn, err = grpc.NewClient("passthrough:///authorized-cri", grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return r.dial(ctx) }),
			grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 2, Jitter: 0.2, MaxDelay: 3 * time.Second}, MinConnectTimeout: r.cfg.ConnectTimeout}),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(r.cfg.MaxMessageBytes), grpc.MaxCallSendMsgSize(64<<10)))
		if err != nil {
			return inv, nil, err
		}
	}
	defer func() {
		if err != nil {
			// Outages break provenance continuity as well as freshness.
			_, _ = r.cfg.Verifier.Verify(ctx, nil)
			r.conn.Close()
			r.conn = nil
		}
	}()
	client := runtimeapi.NewRuntimeServiceClient(r.conn)
	rpcCtx, cancel := context.WithTimeout(ctx, r.cfg.RPCTimeout)
	sandboxes, e := client.ListPodSandbox(rpcCtx, &runtimeapi.ListPodSandboxRequest{}, grpc.WaitForReady(true))
	cancel()
	if e != nil {
		return inv, nil, e
	}
	if sandboxes == nil || len(sandboxes.Items) > r.cfg.MaxSandboxes {
		return inv, nil, errors.New("runtime sandbox budget exceeded")
	}
	rpcCtx, cancel = context.WithTimeout(ctx, r.cfg.RPCTimeout)
	containers, e := client.ListContainers(rpcCtx, &runtimeapi.ListContainersRequest{}, grpc.WaitForReady(true))
	cancel()
	if e != nil {
		return inv, nil, e
	}
	if containers == nil || len(containers.Containers) > r.cfg.MaxContainers {
		return inv, nil, errors.New("runtime container budget exceeded")
	}
	inv = workload.Inventory{Sandboxes: sandboxes.Items, Containers: containers.Containers}
	claims := make([]ProcessClaim, 0, len(inv.Containers))
	seen := make(map[string]bool)
	for _, c := range inv.Containers {
		if ctx.Err() != nil {
			return workload.Inventory{}, nil, ctx.Err()
		}
		if c == nil || c.State != runtimeapi.ContainerState_CONTAINER_RUNNING {
			continue
		}
		if seen[c.Id] {
			return workload.Inventory{}, nil, fmt.Errorf("duplicate runtime container ID")
		}
		seen[c.Id] = true
		rpcCtx, cancel = context.WithTimeout(ctx, r.cfg.RPCTimeout)
		pid, e := r.cfg.Resolver.PID(rpcCtx, client, c)
		cancel()
		if e == nil {
			claims = append(claims, ProcessClaim{ContainerID: c.Id, PID: pid})
		}
		// An individual unprovable container is absent from the new evidence
		// set; it can never inherit its previous binding.
	}
	bindings, err = r.cfg.Verifier.Verify(ctx, claims)
	if err != nil {
		return workload.Inventory{}, nil, err
	}
	// Recheck the runtime assertion after host observation. This detects
	// ordinary exit/restart races but does not replace the explicit live-PID
	// ownership assumption for a runtime that returns stale status.
	byID := make(map[string]*runtimeapi.Container, len(inv.Containers))
	for _, c := range inv.Containers {
		if c != nil {
			byID[c.Id] = c
		}
	}
	for _, claim := range claims {
		rpcCtx, cancel = context.WithTimeout(ctx, r.cfg.RPCTimeout)
		pid, e := r.cfg.Resolver.PID(rpcCtx, client, byID[claim.ContainerID])
		cancel()
		if e != nil || pid != claim.PID {
			return workload.Inventory{}, nil, errors.New("runtime PID claim changed during host verification")
		}
	}
	return inv, bindings, nil
}

func (r *UnixRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.conn != nil {
		err = r.conn.Close()
		r.conn = nil
	}
	return errors.Join(err, r.cfg.Verifier.Close())
}
