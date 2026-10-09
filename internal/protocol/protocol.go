package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"sort"
)

// Counters are decimal strings in JSON to preserve exact values in all clients.
type Envelope struct {
	ProfileID        string `json:"profile_id"`
	DeviceID         string `json:"device_id"`
	Generation       string `json:"generation"`
	OperationID      string `json:"operation_id"`
	ExpectedRevision uint64 `json:"expected_revision,string"`
	Sequence         uint64 `json:"sequence,string"`
	KeyEpoch         uint64 `json:"key_epoch,string"`
	ModeEpoch        uint64 `json:"mode_epoch,string"`
	CipherMode       string `json:"cipher_mode"`
	Payload          []byte `json:"payload"`
	Signature        []byte `json:"signature"`
}

type Member struct {
	DeviceID  string `json:"device_id"`
	PublicKey []byte `json:"public_key"`
	Role      string `json:"role"`
}

type Control struct {
	ProfileID         string   `json:"profile_id"`
	Generation        string   `json:"generation"`
	OperationID       string   `json:"operation_id"`
	ExpectedRevision  uint64   `json:"expected_revision,string"`
	KeyEpoch          uint64   `json:"key_epoch,string"`
	ModeEpoch         uint64   `json:"mode_epoch,string"`
	CipherMode        string   `json:"cipher_mode"`
	OwnerDeviceID     string   `json:"owner_device_id"`
	OwnerPublicKey    []byte   `json:"owner_public_key"`
	Members           []Member `json:"members"`
	Closed            bool     `json:"closed"`
	Signature         []byte   `json:"signature"`
	NewOwnerSignature []byte   `json:"new_owner_signature,omitempty"`
}

func NewID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func ValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, ch := range []byte(id) {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func validCounter(v uint64) bool { return v <= math.MaxInt64 }
func ValidMode(mode string) bool { return mode == "e2ee" || mode == "plaintext" }

func (e Envelope) Validate(maxBytes int64) error {
	for _, id := range []string{e.ProfileID, e.DeviceID, e.Generation, e.OperationID} {
		if !ValidID(id) {
			return errors.New("invalid envelope ID")
		}
	}
	if !validCounter(e.ExpectedRevision) || e.ExpectedRevision == math.MaxInt64 || !validCounter(e.Sequence) || e.Sequence == 0 || !validCounter(e.KeyEpoch) || e.KeyEpoch == 0 || !validCounter(e.ModeEpoch) || e.ModeEpoch == 0 {
		return errors.New("invalid envelope counter")
	}
	if !ValidMode(e.CipherMode) || len(e.Payload) == 0 || int64(len(e.Payload)) > maxBytes || len(e.Signature) != ed25519.SignatureSize {
		return errors.New("invalid envelope payload/mode/signature")
	}
	return nil
}

func field(b *bytes.Buffer, value []byte) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(value)))
	b.Write(value)
}
func counter(b *bytes.Buffer, value uint64) { _ = binary.Write(b, binary.BigEndian, value) }

// SigningBytes is independent of JSON key ordering and signature encoding.
func (e Envelope) SigningBytes() []byte {
	var b bytes.Buffer
	b.WriteString("NX-SYNC-ENVELOPE\x00v1\x00")
	for _, value := range []string{e.ProfileID, e.DeviceID, e.Generation, e.OperationID} {
		field(&b, []byte(value))
	}
	for _, value := range []uint64{e.ExpectedRevision, e.Sequence, e.KeyEpoch, e.ModeEpoch} {
		counter(&b, value)
	}
	field(&b, []byte(e.CipherMode))
	hash := sha256.Sum256(e.Payload)
	b.Write(hash[:])
	return b.Bytes()
}

func (c Control) Validate(maxDevices int) error {
	for _, id := range []string{c.ProfileID, c.Generation, c.OperationID, c.OwnerDeviceID} {
		if !ValidID(id) {
			return errors.New("invalid control ID")
		}
	}
	if !validCounter(c.ExpectedRevision) || c.ExpectedRevision == math.MaxInt64 || c.KeyEpoch == 0 || !validCounter(c.KeyEpoch) || c.ModeEpoch == 0 || !validCounter(c.ModeEpoch) || !ValidMode(c.CipherMode) {
		return errors.New("invalid control counters/mode")
	}
	if len(c.OwnerPublicKey) != ed25519.PublicKeySize || len(c.Signature) != ed25519.SignatureSize || len(c.Members) < 1 || len(c.Members) > maxDevices {
		return errors.New("invalid control membership")
	}
	seen := map[string]bool{}
	owner := false
	for _, member := range c.Members {
		if !ValidID(member.DeviceID) || seen[member.DeviceID] || len(member.PublicKey) != ed25519.PublicKeySize || (member.Role != "writer" && member.Role != "reader") {
			return errors.New("invalid or duplicate member")
		}
		seen[member.DeviceID] = true
		if member.DeviceID == c.OwnerDeviceID {
			owner = member.Role == "writer"
		}
	}
	if !owner {
		return errors.New("owner must be an active writer")
	}
	return nil
}

func (c Control) SigningBytes() []byte {
	var b bytes.Buffer
	b.WriteString("NX-SYNC-CONTROL\x00v1\x00")
	for _, value := range []string{c.ProfileID, c.Generation, c.OperationID} {
		field(&b, []byte(value))
	}
	for _, value := range []uint64{c.ExpectedRevision, c.KeyEpoch, c.ModeEpoch} {
		counter(&b, value)
	}
	field(&b, []byte(c.CipherMode))
	field(&b, []byte(c.OwnerDeviceID))
	field(&b, c.OwnerPublicKey)
	if c.Closed {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	members := append([]Member(nil), c.Members...)
	sort.Slice(members, func(i, j int) bool { return members[i].DeviceID < members[j].DeviceID })
	_ = binary.Write(&b, binary.BigEndian, uint32(len(members)))
	for _, m := range members {
		field(&b, []byte(m.DeviceID))
		field(&b, m.PublicKey)
		field(&b, []byte(m.Role))
	}
	return b.Bytes()
}

func (c Control) ConfirmationBytes() []byte {
	return append([]byte("NX-SYNC-OWNER-CONFIRM\x00v1\x00"), c.SigningBytes()...)
}

type Receipt struct {
	Revision    uint64 `json:"revision,string"`
	OperationID string `json:"operation_id"`
	Replayed    bool   `json:"replayed"`
}

type Head struct {
	DeviceID string `json:"device_id"`
	Revision uint64 `json:"revision,string"`
	Sequence uint64 `json:"sequence,string"`
	Hash     string `json:"sha256"`
}

// State is the authenticated polling cursor. Control and envelope heads are
// read from one transaction; each device retains its own processed cursor.
type State struct {
	ControlRevision uint64 `json:"control_revision,string"`
	KeyEpoch        uint64 `json:"key_epoch,string"`
	ModeEpoch       uint64 `json:"mode_epoch,string"`
	CipherMode      string `json:"cipher_mode"`
	Heads           []Head `json:"heads"`
}

type Health struct {
	ProtocolVersion int    `json:"protocol_version"`
	Status          string `json:"status"`
}
