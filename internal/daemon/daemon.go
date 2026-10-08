package daemon

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"nx-sync-server/internal/api"
	"nx-sync-server/internal/config"
	"nx-sync-server/internal/store"
	"nx-sync-server/internal/tlsutil"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"time"
)

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

func listeners(c config.Config) ([]net.Listener, error) {
	if os.Getenv("LISTEN_FDS") == "" {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			return nil, err
		}
		network := "tcp6"
		if net.ParseIP(host).To4() != nil {
			network = "tcp4"
		}
		l, err := net.Listen(network, c.Listen)
		if err != nil {
			return nil, err
		}
		return []net.Listener{l}, nil
	}
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return nil, errors.New("socket activation PID mismatch")
	}
	count, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || count < 1 || count > 4 {
		return nil, errors.New("invalid inherited listener count")
	}
	_, expected, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return nil, err
	}
	result := make([]net.Listener, 0, count)
	closeAll := func() {
		for _, l := range result {
			_ = l.Close()
		}
	}
	for i := 0; i < count; i++ {
		file := os.NewFile(uintptr(3+i), "systemd-listener")
		if file == nil {
			closeAll()
			return nil, errors.New("missing inherited descriptor")
		}
		l, e := net.FileListener(file)
		_ = file.Close()
		if e != nil {
			closeAll()
			return nil, e
		}
		tcp, ok := l.Addr().(*net.TCPAddr)
		if !ok || strconv.Itoa(tcp.Port) != expected {
			_ = l.Close()
			closeAll()
			return nil, errors.New("inherited listener does not match configured port")
		}
		result = append(result, l)
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")
	return result, nil
}

func Run(ctx context.Context, c config.Config, logger *log.Logger) error {
	if err := c.Validate(); err != nil {
		return err
	}
	debug.SetMemoryLimit(c.MemoryBytes * 3 / 4)
	s, err := store.Open(ctx, c.Database, store.Limits{EnvelopeBytes: c.MaxEnvelopeBytes, ProfileBytes: c.MaxProfileBytes, Devices: c.MaxDevices})
	if err != nil {
		return err
	}
	defer s.Close()
	tlsManager, err := tlsutil.Load(c.TLSKey, c.TLSCertificate, c.TLSHost)
	if err != nil {
		return err
	}
	if err = tlsManager.RenewIfNeeded(time.Now()); err != nil {
		return errors.New("TLS renewal failed before startup")
	}
	ls, err := listeners(c)
	if err != nil {
		return err
	}
	for _, l := range ls {
		defer l.Close()
	}
	server := &http.Server{Handler: api.New(s, c), TLSConfig: tlsManager.Config(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		tlsManager.RunRenewal(childCtx, func() { logger.Print("TLS renewal failed") })
	}()
	errorsCh := make(chan error, len(ls))
	slots := make(chan struct{}, c.MaxConnections)
	for _, l := range ls {
		workers.Add(1)
		go func(l net.Listener) {
			defer workers.Done()
			errorsCh <- server.ServeTLS(&limitedListener{Listener: l, slots: slots}, "", "")
		}(l)
	}
	logger.Print("nx-syncd started")
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errorsCh:
	}
	cancel()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cleanupCancel()
	shutdownErr := server.Shutdown(cleanupCtx)
	if shutdownErr != nil {
		_ = server.Close()
	}
	workers.Wait()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.New("HTTPS listener failed")
	}
	return shutdownErr
}
