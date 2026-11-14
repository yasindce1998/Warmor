package loadphase

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/policyhost/protocol"
)

func TestRejectsDispatchHeldUntilCandidateRejection(t *testing.T) {
	// Force the regression schedule: activation holds eventMu throughout load,
	// rejects, then unlocks. LKG eventually completes, but no longer concurrently.
	var eventMu sync.Mutex
	eventMu.Lock()
	queued, rejected := make(chan struct{}), make(chan struct{})
	completed := make(chan error, 1)
	client, supervisor := net.Pipe()
	defer client.Close()
	defer supervisor.Close()
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		close(queued)
		eventMu.Lock()
		defer eventMu.Unlock()
		<-rejected
		completed <- nil // attributed uncached ALLOW, but only after rejection
	}()
	<-queued
	_ = supervisor.Close() // reject before releasing eventMu, not a wall timeout
	close(rejected)
	eventMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	held := protocol.Control{Version: protocol.Version, Kind: "test-load-held", Digest: "candidate", Sequence: 42}
	if err := Check(ctx, completed, func(ctx context.Context) error { return Confirm(ctx, client, held) }); err == nil {
		t.Fatal("concurrency oracle accepted ALLOW delayed until candidate rejection")
	}
	<-joined
}

func TestRequiresFreshPhaseReceiptAfterCompletion(t *testing.T) {
	client, supervisor := net.Pipe()
	defer client.Close()
	defer supervisor.Close()
	held := protocol.Control{Version: protocol.Version, Kind: "test-load-held", Digest: "candidate", Sequence: 42}
	completed := make(chan error, 1)
	completed <- nil
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		var request protocol.Control
		if err := protocol.Receive(supervisor, &request, protocol.MaxControl); err != nil {
			return
		}
		if request.Kind != "test-load-confirm" {
			return
		}
		_ = protocol.Send(supervisor, held, protocol.MaxControl)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Check(ctx, completed, func(ctx context.Context) error { return Confirm(ctx, client, held) }); err != nil {
		t.Fatal(err)
	}
	<-joined
}

func TestRejectsWrongPhaseReceiptIdentity(t *testing.T) {
	for _, change := range []string{"pid", "digest", "phase", "limits"} {
		t.Run(change, func(t *testing.T) {
			client, supervisor := net.Pipe()
			defer client.Close()
			defer supervisor.Close()
			held := protocol.Control{Version: protocol.Version, Kind: "test-load-held", Digest: "candidate", Sequence: 42}
			wrong := held
			switch change {
			case "pid":
				wrong.Sequence++
			case "digest":
				wrong.Digest = "other-candidate"
			case "phase":
				wrong.Kind = "ready"
			case "limits":
				wrong.Limits.CPUSeconds++
			}
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				var request protocol.Control
				if err := protocol.Receive(supervisor, &request, protocol.MaxControl); err != nil {
					return
				}
				_ = protocol.Send(supervisor, wrong, protocol.MaxControl)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := Confirm(ctx, client, held); err == nil {
				t.Fatal("accepted mismatched phase receipt")
			}
			<-joined
		})
	}
}
