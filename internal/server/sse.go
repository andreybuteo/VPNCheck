package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Hub fans out server-sent events to connected UI clients.
type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
	seq     atomic.Uint64
	// Heartbeat interval; lowered in tests.
	heartbeat time.Duration
}

// NewHub creates an event hub.
func NewHub() *Hub {
	return &Hub{clients: make(map[chan []byte]struct{}), heartbeat: 15 * time.Second}
}

// Publish sends a named event with a JSON payload to all clients.
// Slow clients that cannot keep up drop the event; the UI resynchronises
// through the regular state endpoint.
func (h *Hub) Publish(event string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte(`{"error":"marshal"}`)
	}
	id := h.seq.Add(1)
	msg := []byte(fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", id, event, data))
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}

// ClientCount returns the number of connected SSE clients.
func (h *Hub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

func (h *Hub) subscribe() chan []byte {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

// ServeHTTP streams events. Authentication is enforced by the caller's middleware.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 2000\n\n")
	flusher.Flush()

	ch := h.subscribe()
	defer h.unsubscribe(ch)
	ticker := time.NewTicker(h.heartbeat)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			if _, err := w.Write(msg); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
