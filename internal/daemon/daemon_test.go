package daemon

import (
	"context"
	"io"
	"log"
	"net"
	"path/filepath"
	"testing"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/probe"
	"nx-sync-server/internal/store"
	"nx-sync-server/internal/tlsutil"
)

func TestStandaloneDaemonHTTPSAndShutdown(t *testing.T) {
	dir := t.TempDir()
	c := config.Defaults()
	c.Database = filepath.Join(dir, "settings.sqlite")
	c.TLSKey = filepath.Join(dir, "key")
	c.TLSCertificate = filepath.Join(dir, "cert")
	c.TLSHost = "127.0.0.1"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = l.Addr().String()
	_ = l.Close()
	s, err := store.Create(context.Background(), c.Database, store.Limits{EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	pin, err := tlsutil.Create(c.TLSKey, c.TLSCertificate, c.TLSHost, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, log.New(io.Discard, "", 0)) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		result, err := probe.Check(context.Background(), "https://"+c.Listen, pin, "")
		if err == nil && result.Ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon never became ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown leaked daemon workers")
	}
	if l, err := net.Listen("tcp", c.Listen); err != nil {
		t.Fatalf("listener still owned after shutdown: %v", err)
	} else {
		_ = l.Close()
	}
}
