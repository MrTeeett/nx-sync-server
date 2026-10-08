package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIndependentEnvelopeVector(t *testing.T) {
	data, err := os.ReadFile("testdata/envelope-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Source       string
		PublicKey    []byte `json:"public_key"`
		CanonicalHex string `json:"canonical_hex"`
		Envelope     Envelope
	}
	if err = json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString(vector.CanonicalHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(vector.Envelope.SigningBytes(), expected) {
		t.Fatal("canonical bytes differ from independent vector")
	}
	if err = vector.Envelope.Validate(1024); err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(vector.PublicKey, expected, vector.Envelope.Signature) {
		t.Fatal("independent signature failed")
	}
	if vector.Envelope.ExpectedRevision != 9007199254740993 {
		t.Fatal("large counter was rounded")
	}
}

func TestControlCanonicalOrderingAndDomainSeparation(t *testing.T) {
	a := Member{DeviceID: "11111111111111111111111111111111", PublicKey: make([]byte, 32), Role: "writer"}
	b := Member{DeviceID: "22222222222222222222222222222222", PublicKey: bytes.Repeat([]byte{2}, 32), Role: "reader"}
	c := Control{ProfileID: a.DeviceID, Generation: b.DeviceID, OperationID: a.DeviceID, OwnerDeviceID: a.DeviceID, OwnerPublicKey: a.PublicKey, KeyEpoch: 1, ModeEpoch: 1, CipherMode: "e2ee", Members: []Member{b, a}, Signature: make([]byte, 64)}
	if err := c.Validate(8); err != nil {
		t.Fatal(err)
	}
	signed := c.SigningBytes()
	if c.Members[0].DeviceID != b.DeviceID {
		t.Fatal("signing mutated member order")
	}
	c.Members = []Member{a, b}
	if !bytes.Equal(signed, c.SigningBytes()) {
		t.Fatal("member ordering changed signing bytes")
	}
	if bytes.Equal(signed, c.ConfirmationBytes()) {
		t.Fatal("owner confirmation has no domain separation")
	}
	c.Closed = true
	if bytes.Equal(signed, c.SigningBytes()) {
		t.Fatal("closure is not signed")
	}
	c.Members = []Member{a, a}
	if c.Validate(8) == nil {
		t.Fatal("duplicate member accepted")
	}
}
