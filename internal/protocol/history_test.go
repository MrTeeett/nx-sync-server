package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestHistoryIndependentSigningFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/history-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Manifest  HistoryManifest `json:"manifest"`
		Bytes     string          `json:"signing_bytes_hex"`
		Hash      string          `json:"signing_sha256"`
		PublicKey []byte          `json:"public_key"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if err = fixture.Manifest.Validate(1048576); err != nil {
		t.Fatal(err)
	}
	signed := fixture.Manifest.SigningBytes()
	expected, err := hex.DecodeString(fixture.Bytes)
	if err != nil || !bytes.Equal(signed, expected) {
		t.Fatal("history signing bytes differ from independent fixture")
	}
	digest := sha256.Sum256(signed)
	if hex.EncodeToString(digest[:]) != fixture.Hash || !ed25519.Verify(fixture.PublicKey, signed, fixture.Manifest.Signature) {
		t.Fatal("history signature fixture failed")
	}
	fixture.Manifest.ChatID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if ed25519.Verify(fixture.PublicKey, fixture.Manifest.SigningBytes(), fixture.Manifest.Signature) {
		t.Fatal("signature did not bind the chat")
	}
}

func TestHistoryRejectsUnencryptedAndMalformedManifests(t *testing.T) {
	data, err := os.ReadFile("testdata/history-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Manifest HistoryManifest `json:"manifest"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*HistoryManifest){
		func(m *HistoryManifest) { m.CipherMode = "plaintext" },
		func(m *HistoryManifest) { m.ChatID = "987654321" },
		func(m *HistoryManifest) { m.Sequence = 0 },
		func(m *HistoryManifest) { m.Parts = nil },
		func(m *HistoryManifest) { m.Parts[0].Size = 39 },
		func(m *HistoryManifest) { m.Parts[0].Hash = "00" },
	} {
		m := fixture.Manifest
		m.Parts = append([]HistoryPart(nil), m.Parts...)
		mutate(&m)
		if m.Validate(1048576) == nil {
			t.Fatal("malformed history manifest accepted")
		}
	}
}
