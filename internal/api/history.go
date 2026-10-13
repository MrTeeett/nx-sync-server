package api

import (
	"net/http"
	"strconv"

	"nx-sync-server/internal/protocol"
	"nx-sync-server/internal/store"
)

func historyRoute(w http.ResponseWriter, r *http.Request) (profile, generation, token string, ok bool) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return "", "", "", false
	}
	if !protocol.ValidID(r.PathValue("chat")) || (r.PathValue("device") != "" && !protocol.ValidID(r.PathValue("device"))) {
		failure(w, store.ErrNotFound)
		return "", "", "", false
	}
	return profile, generation, token, true
}

func (h *Handler) historyHeads(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, ok := historyRoute(w, r)
	if !ok {
		return
	}
	heads, err := h.store.HistoryHeads(r.Context(), profile, generation, token, r.PathValue("chat"))
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, 200, struct {
		Heads []protocol.Head `json:"heads"`
	}{heads})
}

func (h *Handler) historyWrite(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, ok := historyRoute(w, r)
	if !ok {
		return
	}
	var m protocol.HistoryManifest
	if !h.decode(w, r, &m, 256*1024) {
		return
	}
	if m.ProfileID != profile || m.Generation != generation || m.ChatID != r.PathValue("chat") ||
		m.DeviceID != r.PathValue("device") || m.Validate(h.config.MaxEnvelopeBytes) != nil {
		writeError(w, 400, "invalid_history")
		return
	}
	var receipt protocol.Receipt
	var err error
	if r.Method == http.MethodPut {
		receipt, err = h.store.BeginHistory(r.Context(), token, m)
	} else {
		receipt, err = h.store.CommitHistory(r.Context(), token, m)
	}
	if err != nil {
		failure(w, err)
		return
	}
	if r.Method == http.MethodPost {
		h.eventsHub.changed(profile)
	}
	writeJSON(w, 200, receipt)
}

func (h *Handler) historyPart(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, ok := historyRoute(w, r)
	if !ok {
		return
	}
	index, err := strconv.Atoi(r.PathValue("part"))
	operation := r.PathValue("operation")
	if err != nil || index < 0 || index >= protocol.MaxHistoryParts || strconv.Itoa(index) != r.PathValue("part") || !protocol.ValidID(operation) {
		failure(w, store.ErrNotFound)
		return
	}
	var body struct {
		Payload []byte `json:"payload"`
	}
	if r.Method == http.MethodPut {
		if !h.decode(w, r, &body, h.config.MaxEnvelopeBytes*2+8192) {
			return
		}
		err = h.store.PutHistoryPart(r.Context(), profile, generation, token, r.PathValue("chat"), r.PathValue("device"), operation, index, body.Payload)
		if err != nil {
			failure(w, err)
			return
		}
		writeJSON(w, 200, struct {
			Stored bool `json:"stored"`
		}{true})
	} else {
		data, revision, err := h.store.ReadHistory(r.Context(), profile, generation, token, r.PathValue("chat"), r.PathValue("device"), operation, index)
		if err != nil {
			failure(w, err)
			return
		}
		w.Header().Set("ETag", `"`+strconv.FormatUint(revision, 10)+`"`)
		body.Payload = data
		writeJSON(w, 200, body)
	}
}

func (h *Handler) historyManifest(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, ok := historyRoute(w, r)
	if !ok {
		return
	}
	data, revision, err := h.store.ReadHistory(r.Context(), profile, generation, token, r.PathValue("chat"), r.PathValue("device"), "", -1)
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatUint(revision, 10)+`"`)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
