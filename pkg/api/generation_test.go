package api

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
)

func TestGenerationContextZeroLeaseAndReplay(t *testing.T) {
	var count atomic.Int32
	e := Event{PolicyGeneration: 42, GenerationContext: NewGenerationContext(0, func() { count.Add(1) })}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.GenerationContext.Complete() }()
	}
	wg.Wait()
	if count.Load() != 1 || e.GenerationContext.ID != 0 {
		t.Fatal("zero lease lost or released twice")
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var replay Event
	if err := json.Unmarshal(data, &replay); err != nil {
		t.Fatal(err)
	}
	if replay.PolicyGeneration != 42 || replay.GenerationContext != nil {
		t.Fatal("kernel ID lost or live dispatch lease replayed")
	}
}
