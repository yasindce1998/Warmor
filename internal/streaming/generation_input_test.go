package streaming

import (
	"sync/atomic"
	"testing"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestPolicyInputSnapshotCannotRetainOrCompleteLiveDispatchOwnership(t *testing.T) {
	var released atomic.Int32
	lease := api.NewGenerationContext(17, func() { released.Add(1) })
	fence := make(chan struct{})
	event := &api.Event{PolicyGeneration: 17, GenerationContext: lease, DispatchBarrier: fence,
		Process: &api.ProcessEvent{Filename: "/tool", Args: []string{"tool", "private-token"}}}
	recorded := FromAPIEvent(event, &api.ActionResult{Action: api.ActionAllow})
	if recorded.PolicyInput.GenerationContext != nil || recorded.PolicyInput.DispatchBarrier != nil || recorded.PolicyInput.PolicyGeneration != 17 {
		t.Fatal("recording retained live dispatch ownership or lost numeric policy identity")
	}
	if event.GenerationContext != lease || event.DispatchBarrier != fence || released.Load() != 0 {
		t.Fatal("recording changed the live producer's ownership")
	}
	recorded.PolicyInput.Process.Args[1] = "changed"
	if event.Process.Args[1] != "private-token" {
		t.Fatal("snapshot shares mutable evaluator input")
	}
	lease.Complete()
	if released.Load() != 1 {
		t.Fatal("snapshot interfered with original lease completion")
	}
}
