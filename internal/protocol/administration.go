package protocol

import (
	"bytes"
	"crypto/sha256"
)

// Administration carries opaque account-encrypted access for trusted owner devices.
type Administration struct {
	ProfileID        string `json:"profile_id"`
	Generation       string `json:"generation"`
	DeviceID         string `json:"device_id"`
	OperationID      string `json:"operation_id"`
	ExpectedRevision uint64 `json:"expected_revision,string"`
	KeyEpoch         uint64 `json:"key_epoch,string"`
	Payload          []byte `json:"payload"`
	Signature        []byte `json:"signature"`
}

// SigningBytes binds the ciphertext digest to the account, device, epoch, and CAS revision.
func (a Administration) SigningBytes() []byte {
	var b bytes.Buffer
	b.WriteString("NX-SYNC-ADMINISTRATION\x00v1\x00")
	for _, value := range []string{a.ProfileID, a.Generation, a.DeviceID, a.OperationID} {
		field(&b, []byte(value))
	}
	counter(&b, a.ExpectedRevision)
	counter(&b, a.KeyEpoch)
	digest := sha256.Sum256(a.Payload)
	b.Write(digest[:])
	return b.Bytes()
}
