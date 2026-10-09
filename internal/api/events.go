package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type eventHub struct {
	mu       sync.Mutex
	profiles map[string]map[chan struct{}]struct{}
}

func (hub *eventHub) subscribe(profile string) (<-chan struct{}, func()) {
	signal := make(chan struct{}, 1)
	hub.mu.Lock()
	if hub.profiles == nil {
		hub.profiles = make(map[string]map[chan struct{}]struct{})
	}
	if hub.profiles[profile] == nil {
		hub.profiles[profile] = make(map[chan struct{}]struct{})
	}
	hub.profiles[profile][signal] = struct{}{}
	hub.mu.Unlock()
	return signal, func() {
		hub.mu.Lock()
		delete(hub.profiles[profile], signal)
		if len(hub.profiles[profile]) == 0 {
			delete(hub.profiles, profile)
		}
		hub.mu.Unlock()
	}
}

// Changes are hints, not a durable event log. Slow clients coalesce hints;
// reconnecting clients always compare the current authenticated state.
func (hub *eventHub) changed(profile string) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	for signal := range hub.profiles[profile] {
		select {
		case signal <- struct{}{}:
		default:
		}
	}
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	select {
	case h.streams <- struct{}{}:
		defer func() { <-h.streams }()
	default:
		writeError(w, http.StatusServiceUnavailable, "overloaded")
		return
	}
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	changed, unsubscribe := h.eventsHub.subscribe(profile)
	defer unsubscribe()
	cursor := func() (string, error) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		state, err := h.store.State(ctx, profile, generation, token)
		if err != nil {
			return "", err
		}
		data, err := json.Marshal(state)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(data)
		return `"` + hex.EncodeToString(digest[:]) + `"`, nil
	}
	current, err := cursor()
	if err != nil {
		failure(w, err)
		return
	}
	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	write := func(event bool, etag string) error {
		if err := controller.SetWriteDeadline(time.Now().Add(8 * time.Second)); err != nil {
			return err
		}
		if event {
			data, err := json.Marshal(struct {
				ETag string `json:"etag"`
			}{etag})
			if err != nil {
				return err
			}
			if _, err = fmt.Fprintf(w, "event: changed\ndata: %s\n\n", data); err != nil {
				return err
			}
		} else if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
			return err
		}
		return controller.Flush()
	}
	if err = write(true, current); err != nil {
		return
	}
	heartbeat := time.NewTicker(45 * time.Second)
	defer heartbeat.Stop()
	lifetime := time.NewTimer(12 * time.Hour)
	defer lifetime.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-lifetime.C:
			return
		case <-changed:
		case <-heartbeat.C:
		}
		next, err := cursor()
		// A removed device/reset never receives another event. All subsequent
		// requests and reconnects must pass normal bearer/generation checks.
		if err != nil {
			return
		}
		if err = write(next != current, next); err != nil {
			return
		}
		current = next
	}
}
