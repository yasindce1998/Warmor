package enforcer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	policycrypto "github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/policyhost"
	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
	"github.com/yasindce1998/warmor/internal/policymeta"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Evaluator is the common decision/metadata/lifecycle boundary. Metadata's raw
// observations are never optimization authority: use Source's effective methods.
type Evaluator interface {
	policymeta.Source
	Evaluate(context.Context, *api.Event) (*api.ActionResult, error)
	Close(context.Context) error
}

// policyBackend owns one complete lifetime, shared only by startup IDs 0/1.
// No runtime or pool exists in the parent for a supervised backend.
type policyBackend struct {
	evaluator Evaluator
	pool      *wasm.Pool
	runtime   *wasm.Runtime
	once      sync.Once
}

func (b *policyBackend) close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		ctx := context.Background()
		_ = b.evaluator.Close(ctx)
		if b.pool != nil {
			_ = b.pool.Close(ctx)
		}
		if b.runtime != nil {
			_ = b.runtime.Close(ctx)
		}
	})
}

type hostEvaluator struct{ *policyhost.Host }

func (h *hostEvaluator) Close(context.Context) error { return h.Host.Close() }

var _ Evaluator = (*hostEvaluator)(nil)
var _ Evaluator = (*wasm.PolicyEvaluator)(nil)

func startSupervisedBackend(ctx context.Context, s *policyhost.Supervisor, path string, key ed25519.PublicKey) (*policyBackend, error) {
	if wasm.IsYAMLPolicy(path) {
		return nil, errors.New("supervised backend requires compiled signed WASM")
	}
	// Resolve the revision once and stage the verified immutable bytes. No WASM
	// header, custom section, ABI, or export is decoded in this process.
	resolved, err := resolvePolicyRevisionPath(path)
	if err != nil {
		return nil, err
	}
	p, err := policyhost.StageFile(resolved, key)
	if err != nil {
		return nil, fmt.Errorf("stage supervised policy: %w", err)
	}
	h, err := s.Start(ctx, p)
	if err != nil {
		return nil, err
	}
	return &policyBackend{evaluator: &hostEvaluator{h}}, nil
}

func inProcessBackend(ctx context.Context, rt *wasm.Runtime, timeout time.Duration) (*policyBackend, error) {
	pool, err := wasm.NewPool(ctx, rt, runtime.NumCPU())
	if err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	hostname, _ := os.Hostname()
	evaluator := wasm.NewPolicyEvaluator(pool, hostname)
	evaluator.SetTimeout(timeout)
	return &policyBackend{evaluator: evaluator, pool: pool, runtime: rt}, nil
}

func (e *Enforcer) candidateBackend(path string, data []byte) (*policyBackend, error) {
	if e.supervisor != nil {
		if data != nil {
			resolved, err := resolvePolicyRevisionPath(path)
			if err != nil {
				return nil, err
			}
			sig, err := policycrypto.ReadFileLimited(resolved+policycrypto.PolicySignatureExt, policycrypto.MaxPolicySignatureFileSize)
			if err != nil {
				return nil, err
			}
			staged, err := policyhost.Stage(data, sig, e.verifyKey)
			if err != nil {
				return nil, err
			}
			h, err := e.supervisor.Start(e.ctx, staged)
			if err != nil {
				return nil, err
			}
			return &policyBackend{evaluator: &hostEvaluator{h}}, nil
		}
		return startSupervisedBackend(e.ctx, e.supervisor, path, e.verifyKey)
	}
	if data == nil {
		rt, pool, err := e.loadPolicyPath(path)
		if err != nil {
			return nil, err
		}
		hostname, _ := os.Hostname()
		ev := wasm.NewPolicyEvaluator(pool, hostname)
		ev.SetTimeout(e.evalTimeout)
		return &policyBackend{evaluator: ev, pool: pool, runtime: rt}, nil
	}
	rt, err := wasm.NewRuntime(e.ctx, wasm.RuntimeConfig{CacheDir: wasm.DefaultCacheDir()})
	if err != nil {
		return nil, err
	}
	if err := rt.LoadPolicyBytes(e.ctx, data); err != nil {
		_ = rt.Close(e.ctx)
		return nil, err
	}
	return inProcessBackend(e.ctx, rt, e.evalTimeout)
}

// Test fixtures may construct an in-process Enforcer directly. Adopt that
// lifetime once, rather than spreading concrete resource checks into slots.
func (e *Enforcer) ownedBackend() *policyBackend {
	if e.backend == nil && e.evaluator != nil {
		e.backend = &policyBackend{evaluator: e.evaluator, pool: e.pool, runtime: e.wasmRuntime}
	}
	return e.backend
}

// DefaultSupervisedConfig is deliberately conservative and contains no module
// trust pins. Administrators must opt in and supply an installed artifact pin.
func DefaultSupervisedConfig(executable, digest string, timeout time.Duration) policyhost.Config {
	if timeout <= 0 {
		timeout = wasm.DefaultEvalTimeout
	}
	return policyhost.Config{Executable: executable, ExecutableSHA256: digest,
		Limits:                protocol.Limits{AddressSpaceBytes: 4 << 30, CPUSeconds: 60, MemoryPages: 256, MaxRequests: 100000},
		InitializationTimeout: 10 * time.Second, LoadTimeout: 5 * time.Second,
		EvaluationTimeout: timeout, MaxHosts: 2}
}
