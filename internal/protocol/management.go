package protocol

import "bytes"

// ServerCommand binds an administrative action to its installation generation.
type ServerCommand struct {
	OperationID string `json:"operation_id"`
	Target      string `json:"target,omitempty"`
	TicketHash  []byte `json:"ticket_hash,omitempty"`
	Signature   []byte `json:"signature"`
}

// SigningBytes encodes the action, account, generation, and operation in a signed domain.
func (c ServerCommand) SigningBytes(action, profile, generation string) []byte {
	var b bytes.Buffer
	b.WriteString("NX-SYNC-SERVER\x00v1\x00")
	for _, v := range []string{action, profile, generation, c.OperationID, c.Target} {
		field(&b, []byte(v))
	}
	field(&b, c.TicketHash)
	return b.Bytes()
}
