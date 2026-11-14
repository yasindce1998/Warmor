package coordinator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/workload"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func inputs() ([]corev1.Pod, workload.Inventory, []workload.Binding) {
	return []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{UID: "uid", Name: "app", Namespace: "team", Labels: map[string]string{"app": "a"}},
			Spec:   corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "main"}}},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "main", ContainerID: "containerd://exact-id", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}},
		workload.Inventory{Containers: []*runtimeapi.Container{{Id: "exact-id", PodSandboxId: "sandbox", Metadata: &runtimeapi.ContainerMetadata{Name: "main"}, State: runtimeapi.ContainerState_CONTAINER_RUNNING}},
			Sandboxes: []*runtimeapi.PodSandbox{{Id: "sandbox", Metadata: &runtimeapi.PodSandboxMetadata{Uid: "uid", Name: "app", Namespace: "team"}, State: runtimeapi.PodSandboxState_SANDBOX_READY}}},
		[]workload.Binding{{CgroupID: 42, Lifetime: "incarnation", ContainerID: "exact-id"}}
}

type pollResult struct {
	inv      workload.Inventory
	bindings []workload.Binding
	err      error
}
type fakePoller struct {
	in     chan pollResult
	closed atomic.Bool
	calls  atomic.Int32
}

func (f *fakePoller) Poll(ctx context.Context) (workload.Inventory, []workload.Binding, error) {
	f.calls.Add(1)
	select {
	case r := <-f.in:
		return r.inv, r.bindings, r.err
	case <-ctx.Done():
		return workload.Inventory{}, nil, ctx.Err()
	}
}
func (f *fakePoller) Close() error { f.closed.Store(true); return nil }

type fakePods struct {
	in   chan []corev1.Pod
	fail chan struct{}
}

func (f *fakePods) Sync(ctx context.Context, publish func([]corev1.Pod) error) error {
	for {
		select {
		case p := <-f.in:
			if err := publish(p); err != nil {
				return err
			}
		case <-f.fail:
			return errors.New("lost watch")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func newTestCoordinator(t *testing.T) (*Coordinator, *fakePoller, *fakePods, context.CancelFunc, <-chan error) {
	t.Helper()
	r := &fakePoller{in: make(chan pollResult, 8)}
	p := &fakePods{in: make(chan []corev1.Pod, 8), fail: make(chan struct{}, 8)}
	cfg := DefaultConfig("node", "containerd")
	cfg.PollInterval = 5 * time.Millisecond
	cfg.PollTimeout = 100 * time.Millisecond
	cfg.MaxAge = 500 * time.Millisecond
	cfg.BackoffMin = time.Millisecond
	cfg.BackoffMax = 4 * time.Millisecond
	cfg.EventBuffer = 1
	c, err := New(cfg, r, p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("Run did not stop")
		}
	})
	return c, r, p, cancel, done
}

func TestCoordinatorRetirementImmutabilityAndShutdown(t *testing.T) {
	c, r, p, cancel, _ := newTestCoordinator(t)
	pods, inv, bindings := inputs()
	if c.Current().Ready() {
		t.Fatal("startup ready")
	}
	r.in <- pollResult{inv: inv, bindings: bindings}
	p.in <- pods
	eventually(t, func() bool { return c.Current().Ready() })
	old := c.Current()
	id, reason := old.Lookup(42, "incarnation")
	if reason != workload.Verified || id.PodUID() != "uid" {
		t.Fatalf("lookup %v %s", id, reason)
	}
	labels := id.Labels()
	labels["app"] = "forged"
	if id.Labels()["app"] != "a" {
		t.Fatal("label alias")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				c.Current().Lookup(42, "incarnation")
			}
		}()
	}
	// Same-name recreation with no matching runtime status cannot retain UID.
	newPod := *pods[0].DeepCopy()
	newPod.UID = "replacement"
	p.in <- []corev1.Pod{newPod}
	eventually(t, func() bool { return c.Current().Epoch() > old.Epoch() })
	if _, reason := old.Lookup(42, "incarnation"); reason != Unavailable {
		t.Fatal("retained view remained usable")
	}
	if _, reason := c.Current().Lookup(42, "incarnation"); reason == workload.Verified {
		t.Fatal("recreation inherited identity")
	}
	p.in <- nil
	r.in <- pollResult{} // authoritative empty runtime inventory/bindings
	eventually(t, func() bool {
		_, reason := c.Current().Lookup(42, "incarnation")
		return c.Current().Ready() && reason == workload.UnknownCgroup
	})
	wg.Wait()
	if c.DroppedEvents() == 0 {
		t.Fatal("unbounded/blocking event delivery")
	}
	cancel()
	eventually(t, func() bool { return r.closed.Load() })
	if c.Current().Ready() {
		t.Fatal("ready after stop")
	}
	if err := c.Run(context.Background()); err == nil {
		t.Fatal("second Run accepted")
	}
}

func TestCoordinatorSourceFailureAndLeaseExpiry(t *testing.T) {
	c, r, p, _, _ := newTestCoordinator(t)
	pods, inv, b := inputs()
	r.in <- pollResult{inv: inv, bindings: b}
	p.in <- pods
	eventually(t, func() bool { return c.Current().Ready() })
	view := c.Current()
	r.in <- pollResult{err: errors.New("runtime lost")}
	eventually(t, func() bool { return !c.Current().Ready() })
	if _, reason := view.Lookup(42, "incarnation"); reason != Unavailable {
		t.Fatal("old runtime identity retained")
	}
	r.in <- pollResult{inv: inv, bindings: b}
	eventually(t, func() bool { return c.Current().Ready() })
	p.fail <- struct{}{}
	eventually(t, func() bool { return !c.Current().Ready() })
	// A lease enforces time locally even if no new publication is made.
	c.mu.Lock()
	c.podSet = pods
	c.inventory = inv
	c.bindings = b
	c.podUntil = time.Now().Add(5 * time.Millisecond)
	c.runtimeUntil = c.podUntil
	c.publishLocked("test")
	c.mu.Unlock()
	v := c.Current()
	time.Sleep(10 * time.Millisecond)
	if _, reason := v.Lookup(42, "incarnation"); reason != Unavailable {
		t.Fatal("expired lease accepted")
	}
}

func TestCoordinatorBudgetsAndConfig(t *testing.T) {
	c, r, p, _, _ := newTestCoordinator(t)
	pods, inv, b := inputs()
	p.in <- pods
	r.in <- pollResult{inv: inv, bindings: make([]workload.Binding, c.cfg.MaxBindings+1)}
	eventually(t, func() bool { return c.Current().Epoch() > 0 })
	if c.Current().Ready() {
		t.Fatal("oversized input accepted")
	}
	r.in <- pollResult{inv: inv, bindings: b}
	p.in <- pods
	eventually(t, func() bool { return c.Current().Ready() })
	foreign := *pods[0].DeepCopy()
	foreign.Spec.NodeName = "other"
	p.in <- []corev1.Pod{foreign}
	eventually(t, func() bool { return !c.Current().Ready() })
	for _, mutate := range []func(*Config){func(c *Config) { c.NodeName = "" }, func(c *Config) { c.Runtime = "bad://" }, func(c *Config) { c.MaxAge = 0 }, func(c *Config) { c.MaxPods = 0 }, func(c *Config) { c.EventBuffer = 0 }} {
		cfg := DefaultConfig("node", "containerd")
		mutate(&cfg)
		if _, err := New(cfg, r, p); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	if _, err := New(DefaultConfig("node", "containerd"), nil, p); err == nil {
		t.Fatal("nil runtime accepted")
	}
}
