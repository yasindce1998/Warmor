package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

//go:embed assets/index.html
var assets embed.FS

// Event represents a policy evaluation event for the dashboard.
type Event struct {
	Time   time.Time `json:"time"`
	PID    uint32    `json:"pid"`
	Comm   string    `json:"comm"`
	Action string    `json:"action"`
	Reason string    `json:"reason"`
}

// Handler serves the SSE dashboard and broadcasts events to connected clients.
type Handler struct {
	mu      sync.RWMutex
	clients map[chan Event]struct{}
	ring    []Event
	ringPos int
	ringCap int
}

// New creates a dashboard handler with a ring buffer of the given capacity.
func New(ringCap int) *Handler {
	if ringCap <= 0 {
		ringCap = 100
	}
	return &Handler{
		clients: make(map[chan Event]struct{}),
		ring:    make([]Event, 0, ringCap),
		ringCap: ringCap,
	}
}

// Publish sends an event to all connected SSE clients and stores it in the ring buffer.
func (h *Handler) Publish(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}

	h.mu.Lock()
	if len(h.ring) < h.ringCap {
		h.ring = append(h.ring, e)
	} else {
		h.ring[h.ringPos] = e
	}
	h.ringPos = (h.ringPos + 1) % h.ringCap

	clients := make([]chan Event, 0, len(h.clients))
	for ch := range h.clients {
		clients = append(clients, ch)
	}
	h.mu.Unlock()

	for _, ch := range clients {
		select {
		case ch <- e:
		default:
		}
	}
}

// History returns a copy of buffered events in chronological order.
func (h *Handler) History() []Event {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.ring) < h.ringCap {
		out := make([]Event, len(h.ring))
		copy(out, h.ring)
		return out
	}

	out := make([]Event, h.ringCap)
	copy(out, h.ring[h.ringPos:])
	copy(out[h.ringCap-h.ringPos:], h.ring[:h.ringPos])
	return out
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/dashboard":
		h.serveIndex(w, r)
	case "/dashboard/events":
		h.serveSSE(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveIndex(w http.ResponseWriter, _ *http.Request) {
	data, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (h *Handler) serveSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan Event, 64)

	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
	}()

	// Send historical events
	for _, e := range h.History() {
		writeSSEEvent(w, e)
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			writeSSEEvent(w, e)
			flusher.Flush()
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, e Event) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: policy_eval\ndata: %s\n\n", data)
}
