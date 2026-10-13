package api

import (
	"net/http"
	"path/filepath"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/protocol"
	"nx-sync-server/internal/store"
)

func (h *Handler) serverInfo(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	access, err := h.store.ServerAccess(r.Context(), profile, generation, token)
	if err != nil {
		failure(w, err)
		return
	}
	var updates config.ServerUpdates
	if err = fsutil.ReadJSON(filepath.Join(filepath.Dir(h.config.Database), "server-status.json"), &updates, 8192); err != nil {
		updates = config.ServerUpdates{Status: "unknown"}
	}
	writeJSON(w, http.StatusOK, struct {
		Version string               `json:"version"`
		Access  store.ServerAccess   `json:"access"`
		Updates config.ServerUpdates `json:"updates"`
	}{config.Version, access, updates})
}

func (h *Handler) describeDevice(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	var description store.DeviceDescription
	if !h.decode(w, r, &description, 2048) {
		return
	}
	if err = h.store.DescribeDevice(r.Context(), profile, generation, token, description); err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Saved bool `json:"saved"`
	}{true})
}

func (h *Handler) serverAccounts(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	accounts, err := h.store.ServerAccounts(r.Context(), profile, generation, token, r.PathValue("after"))
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accounts)
}

func (h *Handler) accountInvitation(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	var command protocol.ServerCommand
	if !h.decode(w, r, &command, 2048) {
		return
	}
	expires, err := h.store.InviteAccount(r.Context(), profile, generation, token, command)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Expires int64 `json:"expires_at,string"`
	}{expires})
}

func (h *Handler) revokeAccounts(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	var command protocol.ServerCommand
	if !h.decode(w, r, &command, 2048) {
		return
	}
	profiles, err := h.store.RevokeAccounts(r.Context(), profile, generation, token, command)
	if err != nil {
		failure(w, err)
		return
	}
	for _, revoked := range profiles {
		h.eventsHub.changed(revoked)
	}
	writeJSON(w, http.StatusOK, struct {
		Revoked int `json:"revoked"`
	}{len(profiles)})
}

func (h *Handler) administration(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	state, err := h.store.Administration(r.Context(), profile, generation, token)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *Handler) putAdministration(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	var packet protocol.Administration
	if !h.decode(w, r, &packet, 40<<10) {
		return
	}
	if packet.ProfileID != profile || packet.Generation != generation {
		failure(w, store.ErrForbidden)
		return
	}
	receipt, err := h.store.PutAdministration(r.Context(), token, packet)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}
