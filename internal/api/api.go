package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/protocol"
	"nx-sync-server/internal/store"
	"strconv"
	"strings"
	"time"
)

type Handler struct {
	store  *store.Store
	config config.Config
	active chan struct{}
}

func New(s *store.Store, c config.Config) http.Handler {
	h := &Handler{store: s, config: c, active: make(chan struct{}, c.MaxRequests)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /v1/profiles/{profile}/heads", h.heads)
	mux.HandleFunc("GET /v1/profiles/{profile}/envelopes/{device}", h.envelope)
	mux.HandleFunc("PUT /v1/profiles/{profile}/envelopes/{device}", h.publish)
	mux.HandleFunc("GET /v1/profiles/{profile}/control", h.control)
	mux.HandleFunc("PUT /v1/profiles/{profile}/control", h.putControl)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		select {
		case h.active <- struct{}{}:
			defer func() { <-h.active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeError(w, 503, "overloaded")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, struct {
		Code string `json:"code"`
	}{Code: code})
}
func failure(w http.ResponseWriter, err error) {
	status, code := 503, "storage_unavailable"
	switch {
	case errors.Is(err, store.ErrUnauthorized):
		status, code = 401, "unauthorized"
	case errors.Is(err, store.ErrForbidden):
		status, code = 403, "forbidden"
	case errors.Is(err, store.ErrConflict):
		status, code = 409, "revision_conflict"
	case errors.Is(err, store.ErrReplay):
		status, code = 409, "operation_conflict"
	case errors.Is(err, store.ErrEpoch):
		status, code = 409, "stale_epoch"
	case errors.Is(err, store.ErrGeneration):
		status, code = 409, "server_reset"
	case errors.Is(err, store.ErrClosed):
		status, code = 410, "profile_deleted"
	case errors.Is(err, store.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(err, store.ErrQuota):
		status, code = 413, "quota_exceeded"
	}
	if status == 503 {
		w.Header().Set("Retry-After", "1")
	}
	writeError(w, status, code)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancel()
	status, state := 200, "ready"
	if h.store.Health(ctx) != nil {
		status, state = 503, "not_ready"
	}
	writeJSON(w, status, protocol.Health{ProtocolVersion: config.ProtocolVersion, Status: state})
}

func auth(r *http.Request) (string, string, string, error) {
	profile := r.PathValue("profile")
	generation := r.Header.Get("X-NX-Generation")
	header := r.Header.Get("Authorization")
	if !protocol.ValidID(profile) || !protocol.ValidID(generation) || !strings.HasPrefix(header, "Bearer ") {
		return "", "", "", store.ErrUnauthorized
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if len(token) != 43 {
		return "", "", "", store.ErrUnauthorized
	}
	return profile, generation, token, nil
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, value any, limit int64) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, 415, "json_required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	if err := fsutil.DecodeJSON(r.Body, value); err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			writeError(w, 413, "body_too_large")
		} else {
			writeError(w, 400, "invalid_request")
		}
		return false
	}
	return true
}

func (h *Handler) heads(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	heads, err := h.store.Heads(r.Context(), profile, generation, token)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, 200, heads)
}
func (h *Handler) envelope(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	data, revision, err := h.store.ReadEnvelope(r.Context(), profile, generation, token, r.PathValue("device"))
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatUint(revision, 10)+`"`)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
func (h *Handler) publish(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	var e protocol.Envelope
	if !h.decode(w, r, &e, h.config.MaxEnvelopeBytes*2+8192) {
		return
	}
	if e.ProfileID != profile || e.Generation != generation || e.DeviceID != r.PathValue("device") || e.Validate(h.config.MaxEnvelopeBytes) != nil {
		writeError(w, 400, "invalid_envelope")
		return
	}
	receipt, err := h.store.Publish(r.Context(), token, e)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, 200, receipt)
}
func (h *Handler) control(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	data, revision, err := h.store.ReadControl(r.Context(), profile, generation, token)
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatUint(revision, 10)+`"`)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
func (h *Handler) putControl(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	var c protocol.Control
	if !h.decode(w, r, &c, 64<<10) {
		return
	}
	if c.ProfileID != profile || c.Generation != generation || c.Validate(h.config.MaxDevices) != nil {
		writeError(w, 400, "invalid_control")
		return
	}
	receipt, err := h.store.PutControl(r.Context(), token, c)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, 200, receipt)
}
