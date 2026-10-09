package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
)

func ValidToken(token string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
}

// A bootstrap ticket is minted locally by the administrator. It authorizes
// one profile, with all private keys generated and retained by its client.
type BootstrapClaim struct {
	Ticket    string  `json:"ticket"`
	Token     string  `json:"token"`
	Control   Control `json:"control"`
	Signature []byte  `json:"signature"`
}

func (c BootstrapClaim) SigningBytes() []byte {
	var b bytes.Buffer
	b.WriteString("NX-SYNC-BOOTSTRAP\x00v1\x00")
	field(&b, []byte(c.Ticket))
	field(&b, []byte(c.Token))
	hash := sha256.Sum256(c.Control.SigningBytes())
	b.Write(hash[:])
	return b.Bytes()
}

// TicketHash and Box have independent secrets. The server receives only the
// ticket used for authorization, never the key decrypting the invitation box.
type Invitation struct {
	ProfileID        string `json:"profile_id"`
	Generation       string `json:"generation"`
	OperationID      string `json:"operation_id"`
	ExpectedRevision uint64 `json:"expected_revision,string"`
	DeviceID         string `json:"device_id"`
	TicketHash       []byte `json:"ticket_hash"`
	Box              []byte `json:"box"`
	Signature        []byte `json:"signature"`
}

func (i Invitation) SigningBytes() []byte {
	var b bytes.Buffer
	b.WriteString("NX-SYNC-INVITE\x00v1\x00")
	for _, value := range []string{i.ProfileID, i.Generation, i.OperationID, i.DeviceID} {
		field(&b, []byte(value))
	}
	counter(&b, i.ExpectedRevision)
	b.Write(i.TicketHash)
	hash := sha256.Sum256(i.Box)
	b.Write(hash[:])
	return b.Bytes()
}

type InvitationClaim struct {
	ProfileID   string `json:"profile_id"`
	Generation  string `json:"generation"`
	DeviceID    string `json:"device_id"`
	OperationID string `json:"operation_id"`
	Ticket      string `json:"ticket"`
	Token       string `json:"token"`
	Signature   []byte `json:"signature"`
}

func (c InvitationClaim) SigningBytes() []byte {
	var b bytes.Buffer
	b.WriteString("NX-SYNC-JOIN\x00v1\x00")
	for _, value := range []string{c.ProfileID, c.Generation, c.DeviceID, c.OperationID, c.Ticket, c.Token} {
		field(&b, []byte(value))
	}
	return b.Bytes()
}
