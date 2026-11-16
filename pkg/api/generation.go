package api

import "sync"

// GenerationContext is a live dispatch lease. ID zero is a valid captured
// legacy generation, distinct from an event which has not been captured yet.
// It is not serialized: replayed JSON must acquire a fresh dispatch lease.
type GenerationContext struct {
	ID   uint64
	once sync.Once
	done func()
}

func NewGenerationContext(id uint64, done func()) *GenerationContext {
	return &GenerationContext{ID: id, done: done}
}

// Complete releases the lease exactly once, including canceled delivery.
func (g *GenerationContext) Complete() {
	if g != nil {
		g.once.Do(func() {
			if g.done != nil {
				g.done()
			}
		})
	}
}
