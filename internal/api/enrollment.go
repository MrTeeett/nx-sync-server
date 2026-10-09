package api

import (
	"net/http"
	"nx-sync-server/internal/protocol"
)

func (h *Handler) bootstrap(w http.ResponseWriter, r *http.Request) {
	var claim protocol.BootstrapClaim
	if !h.decode(w, r, &claim, 64<<10) {
		return
	}
	credential, err := h.store.ClaimBootstrap(r.Context(), claim)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, credential)
}

func (h *Handler) invite(w http.ResponseWriter, r *http.Request) {
	profile, generation, token, err := auth(r)
	if err != nil {
		failure(w, err)
		return
	}
	var invitation protocol.Invitation
	if !h.decode(w, r, &invitation, 32<<10) {
		return
	}
	if invitation.ProfileID != profile || invitation.Generation != generation {
		writeError(w, 400, "invalid_invitation")
		return
	}
	expires, err := h.store.Invite(r.Context(), token, invitation)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Expires int64 `json:"expires_at,string"`
	}{expires})
}

func (h *Handler) join(w http.ResponseWriter, r *http.Request) {
	var claim protocol.InvitationClaim
	if !h.decode(w, r, &claim, 8192) {
		return
	}
	result, err := h.store.ClaimInvitation(r.Context(), claim)
	if err != nil {
		failure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
