package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"nx-sync-server/internal/protocol"
)

func historyFixture(t *testing.T, f *fixture, chat string, revision, sequence uint64, pages ...[]byte) protocol.HistoryManifest {
	t.Helper()
	m := protocol.HistoryManifest{ProfileID: f.credential.ProfileID, DeviceID: f.credential.DeviceID,
		Generation: f.credential.Generation, OperationID: id(t), ChatID: chat, ExpectedRevision: revision,
		Sequence: sequence, KeyEpoch: f.control.KeyEpoch, ModeEpoch: f.control.ModeEpoch, CipherMode: "e2ee"}
	for _, page := range pages {
		hash := sha256.Sum256(page)
		m.Parts = append(m.Parts, protocol.HistoryPart{Size: uint64(len(page)), Hash: hex.EncodeToString(hash[:])})
	}
	m.Signature = ed25519.Sign(f.deviceKey, m.SigningBytes())
	return m
}

func putHistoryPages(t *testing.T, f *fixture, m protocol.HistoryManifest, pages ...[]byte) {
	t.Helper()
	for i, page := range pages {
		if err := f.s.PutHistoryPart(context.Background(), m.ProfileID, m.Generation, f.credential.Token, m.ChatID, m.DeviceID, m.OperationID, i, page); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHistoryAtomicReplacementAndRetry(t *testing.T) {
	f := setup(t)
	f.s.limits.ProfileBytes = 16384
	ctx := context.Background()
	chat := id(t)
	p1, p2 := bytes.Repeat([]byte{0xa1}, 64), bytes.Repeat([]byte{0xb2}, 64)
	m := historyFixture(t, f, chat, 0, 1, p1, p2)
	if _, err := f.s.BeginHistory(ctx, f.credential.Token, m); err != nil {
		t.Fatal(err)
	}
	if heads, err := f.s.HistoryHeads(ctx, m.ProfileID, m.Generation, f.credential.Token, chat); err != nil || len(heads) != 0 {
		t.Fatalf("staged heads=%v err=%v", heads, err)
	}
	putHistoryPages(t, f, m, p1)
	if _, err := f.s.CommitHistory(ctx, f.credential.Token, m); !errors.Is(err, ErrConflict) {
		t.Fatalf("partial commit: %v", err)
	}
	putHistoryPages(t, f, m, p1, p2)
	if r, err := f.s.CommitHistory(ctx, f.credential.Token, m); err != nil || r.Revision != 1 || r.Replayed {
		t.Fatalf("commit=%+v err=%v", r, err)
	}
	if r, err := f.s.CommitHistory(ctx, f.credential.Token, m); err != nil || !r.Replayed {
		t.Fatalf("retry=%+v err=%v", r, err)
	}
	next := historyFixture(t, f, chat, 1, 2, p2)
	if _, err := f.s.BeginHistory(ctx, f.credential.Token, next); err != nil {
		t.Fatal(err)
	}
	if data, revision, err := f.s.ReadHistory(ctx, m.ProfileID, m.Generation, f.credential.Token, chat, m.DeviceID, m.OperationID, 1); err != nil || revision != 1 || !bytes.Equal(data, p2) {
		t.Fatalf("old copy unavailable while staging: %v", err)
	}
	putHistoryPages(t, f, next, p2)
	if _, err := f.s.CommitHistory(ctx, f.credential.Token, next); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.ReadHistory(ctx, m.ProfileID, m.Generation, f.credential.Token, chat, m.DeviceID, m.OperationID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old snapshot retained: %v", err)
	}
	if r, err := f.s.BeginHistory(ctx, f.credential.Token, m); err != nil || !r.Replayed || r.Revision != 1 {
		t.Fatalf("lost-response replay=%+v err=%v", r, err)
	}
}

func TestHistoryChatIsolationTamperingQuotaAndEpochClear(t *testing.T) {
	f := setup(t)
	f.s.limits.ProfileBytes = 16384
	ctx := context.Background()
	page := bytes.Repeat([]byte{0x42}, 64)
	m := historyFixture(t, f, id(t), 0, 1, page)
	changed := m
	changed.ChatID = id(t)
	if _, err := f.s.BeginHistory(ctx, f.credential.Token, changed); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unsigned chat mutation: %v", err)
	}
	if _, err := f.s.BeginHistory(ctx, f.credential.Token, m); err != nil {
		t.Fatal(err)
	}
	if err := f.s.PutHistoryPart(ctx, m.ProfileID, m.Generation, f.credential.Token, m.ChatID, m.DeviceID, m.OperationID, 0, bytes.Repeat([]byte{0x43}, 64)); !errors.Is(err, ErrConflict) {
		t.Fatalf("part mutation: %v", err)
	}
	putHistoryPages(t, f, m, page)
	if _, err := f.s.CommitHistory(ctx, f.credential.Token, m); err != nil {
		t.Fatal(err)
	}
	if heads, err := f.s.HistoryHeads(ctx, m.ProfileID, m.Generation, f.credential.Token, changed.ChatID); err != nil || len(heads) != 0 {
		t.Fatalf("cross-chat heads=%v err=%v", heads, err)
	}
	staged := historyFixture(t, f, id(t), 0, 1, page)
	if _, err := f.s.BeginHistory(ctx, f.credential.Token, staged); err != nil {
		t.Fatal(err)
	}
	f.s.limits.ProfileBytes = 1
	if _, err := f.s.Publish(ctx, f.credential.Token, f.envelope(t)); !errors.Is(err, ErrQuota) {
		t.Fatalf("archive omitted from settings quota: %v", err)
	}
	f.s.limits.ProfileBytes = 16384
	c := f.control
	c.ExpectedRevision = 1
	c.ModeEpoch++
	if _, err := f.change(t, c); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []protocol.HistoryManifest{m, staged} {
		if heads, err := f.s.HistoryHeads(ctx, m.ProfileID, m.Generation, f.credential.Token, snapshot.ChatID); err != nil || len(heads) != 0 {
			t.Fatalf("clear did not remove archive: %v %v", heads, err)
		}
	}
	if _, err := f.s.CommitHistory(ctx, f.credential.Token, staged); !errors.Is(err, ErrEpoch) {
		t.Fatalf("stale stage recreated cleared cloud: %v", err)
	}
}

func TestHistoryPersistsAcrossRestart(t *testing.T) {
	f := setup(t)
	f.s.limits.ProfileBytes = 16384
	ctx := context.Background()
	page := bytes.Repeat([]byte{0x99}, 64)
	m := historyFixture(t, f, id(t), 0, 1, page)
	if _, err := f.s.BeginHistory(ctx, f.credential.Token, m); err != nil {
		t.Fatal(err)
	}
	putHistoryPages(t, f, m, page)
	if _, err := f.s.CommitHistory(ctx, f.credential.Token, m); err != nil {
		t.Fatal(err)
	}
	limits := f.s.limits
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.s, err = Open(ctx, f.path, limits)
	if err != nil {
		t.Fatal(err)
	}
	if data, revision, err := f.s.ReadHistory(ctx, m.ProfileID, m.Generation, f.credential.Token, m.ChatID, m.DeviceID, m.OperationID, 0); err != nil || revision != 1 || !bytes.Equal(data, page) {
		t.Fatalf("restart revision=%v err=%v", revision, err)
	}
	state, err := f.s.State(ctx, m.ProfileID, m.Generation, f.credential.Token)
	if err != nil || state.HistoryRevision != 1 {
		t.Fatalf("notification cursor=%+v err=%v", state, err)
	}
}
