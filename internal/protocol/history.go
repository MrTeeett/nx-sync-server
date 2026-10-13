package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
)

const MaxHistoryParts = 1024

// ChatID is a client-keyed opaque identifier, never a Telegram peer ID.
// The signed manifest commits a complete encrypted snapshot for one chat.
type HistoryManifest struct {
	ProfileID        string        `json:"profile_id"`
	DeviceID         string        `json:"device_id"`
	Generation       string        `json:"generation"`
	OperationID      string        `json:"operation_id"`
	ChatID           string        `json:"chat_id"`
	ExpectedRevision uint64        `json:"expected_revision,string"`
	Sequence         uint64        `json:"sequence,string"`
	KeyEpoch         uint64        `json:"key_epoch,string"`
	ModeEpoch        uint64        `json:"mode_epoch,string"`
	CipherMode       string        `json:"cipher_mode"`
	Parts            []HistoryPart `json:"parts"`
	Signature        []byte        `json:"signature"`
}

type HistoryPart struct {
	Size uint64 `json:"size,string"`
	Hash string `json:"sha256"`
}

func (m HistoryManifest) Validate(maxPartBytes int64) error {
	for _, id := range []string{m.ProfileID, m.DeviceID, m.Generation, m.OperationID, m.ChatID} {
		if !ValidID(id) {
			return errors.New("invalid history ID")
		}
	}
	if m.ExpectedRevision >= math.MaxInt64 || !validCounter(m.Sequence) || m.Sequence == 0 ||
		!validCounter(m.KeyEpoch) || m.KeyEpoch == 0 || !validCounter(m.ModeEpoch) || m.ModeEpoch == 0 ||
		m.CipherMode != "e2ee" || len(m.Signature) != ed25519.SignatureSize ||
		len(m.Parts) == 0 || len(m.Parts) > MaxHistoryParts {
		return errors.New("invalid history manifest")
	}
	for _, p := range m.Parts {
		hash, err := hex.DecodeString(p.Hash)
		if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != p.Hash ||
			p.Size < 40 || p.Size > uint64(maxPartBytes) {
			return errors.New("invalid history part")
		}
	}
	return nil
}

func (m HistoryManifest) SigningBytes() []byte {
	var b bytes.Buffer
	b.WriteString("NX-SYNC-HISTORY\x00v1\x00")
	for _, value := range []string{m.ProfileID, m.DeviceID, m.Generation, m.OperationID, m.ChatID} {
		field(&b, []byte(value))
	}
	for _, value := range []uint64{m.ExpectedRevision, m.Sequence, m.KeyEpoch, m.ModeEpoch} {
		counter(&b, value)
	}
	field(&b, []byte(m.CipherMode))
	_ = binary.Write(&b, binary.BigEndian, uint32(len(m.Parts)))
	for _, p := range m.Parts {
		counter(&b, p.Size)
		hash, _ := hex.DecodeString(p.Hash) // Validate precedes verification.
		b.Write(hash)
	}
	return b.Bytes()
}
