package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/port"
)

func (m *Manager) render(man Manifest) (string, string) {
	// All paths come from Layout and TLS host/listen are validated data. Quote
	// systemd path arguments, escaping specifier expansion for unusual test roots.
	q := func(s string) string { return strconv.Quote(strings.ReplaceAll(s, "%", "%%")) }
	service := fmt.Sprintf(`[Unit]
Description=NX settings sync HTTPS server (%s)
Requires=nx-syncd.socket
After=network.target nx-syncd.socket

[Service]
Type=simple
User=%d
Group=%d
ExecStart=%s --config %s
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
UMask=0077
MemoryMax=%d
MemoryHigh=%d
MemorySwapMax=0
TasksMax=128
Environment=GOMEMLIMIT=%d
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=%s
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
`, man.InstallationID, man.UID, man.GID, q(filepath.Join(m.Layout.app(), "current", "nx-syncd")), q(filepath.Join(m.Layout.conf(), "config.json")), man.Config.MemoryBytes, man.Config.MemoryBytes*7/8, man.Config.MemoryBytes*3/4, q(m.Layout.data()))
	socket := fmt.Sprintf(`[Unit]
Description=NX settings sync socket (%s)

[Socket]
ListenStream=%s
Accept=no
Service=nx-syncd.service
NoDelay=true
Backlog=64
BindIPv6Only=ipv6-only

[Install]
WantedBy=sockets.target
`, man.InstallationID, man.Config.Listen)
	return service, socket
}

func verifyOwnedFile(path, hash, previous string) error {
	data, err := readRegular(path, 128<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if hash == "" || digest(data) != hash && (previous == "" || digest(data) != previous) {
		return errors.New("owned unit changed; refusing to change or stop a foreign unit")
	}
	return nil
}

func (m *Manager) checkUnits(man Manifest) error {
	if err := m.directories(&man, false); err != nil {
		return err
	}
	for _, p := range []string{m.Layout.service() + ".d", m.Layout.socket() + ".d"} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			return errors.New("untracked systemd drop-in; refusing service changes")
		}
	}
	if err := verifyOwnedFile(m.Layout.service(), man.ServiceHash, man.PreviousServiceHash); err != nil {
		return err
	}
	return verifyOwnedFile(m.Layout.socket(), man.SocketHash, man.PreviousSocketHash)
}

func (m *Manager) writeUnits(man *Manifest) error {
	if err := m.checkUnits(*man); err != nil {
		return err
	}
	service, socket := m.render(*man)
	man.PreviousServiceHash = man.ServiceHash
	man.PreviousSocketHash = man.SocketHash
	man.ServiceHash = digest([]byte(service))
	man.SocketHash = digest([]byte(socket))
	if err := m.save(*man); err != nil {
		return err
	} // Record ownership before writes.
	parent := filepath.Dir(m.Layout.service())
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe shared systemd directory")
	}
	if err := fsutil.WriteJSON(filepath.Join(m.Layout.conf(), "config.json"), man.Config, 0640); err != nil {
		return err
	}
	if err := os.Chown(filepath.Join(m.Layout.conf(), "config.json"), os.Geteuid(), man.GID); err != nil {
		return err
	}
	if err := fsutil.AtomicWrite(m.Layout.service(), []byte(service), 0644); err != nil {
		return err
	}
	if err := fsutil.AtomicWrite(m.Layout.socket(), []byte(socket), 0644); err != nil {
		return err
	}
	man.PreviousServiceHash = ""
	man.PreviousSocketHash = ""
	return m.save(*man)
}

func (m *Manager) startSocket(ctx context.Context, man *Manifest) error {
	for attempts := 0; attempts < 101; attempts++ {
		if err := m.writeUnits(man); err != nil {
			return err
		}
		if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if _, err := m.Runner.Run(ctx, "systemctl", "start", "nx-syncd.socket"); err == nil {
			return nil
		} else {
			if !man.AutoPort || man.Rule != nil {
				return errors.New("configured socket could not bind; manual port is never replaced")
			}
			// Only a confirmed busy port warrants choosing a different candidate.
			bindHost, bindPort, _ := net.SplitHostPort(man.Config.Listen)
			bindNumber, _ := strconv.Atoi(bindPort)
			l, bindErr := port.Reserve(ctx, port.Policy{Host: bindHost, Port: bindNumber, BlockWebPorts: man.Config.BlockWebPorts})
			if bindErr == nil {
				_ = l.Close()
				return err
			}
			if !errors.Is(bindErr, syscall.EADDRINUSE) {
				return err
			}
			_, text, _ := net.SplitHostPort(man.Config.Listen)
			number, _ := strconv.Atoi(text)
			if number >= 18543 {
				return errors.New("automatic port range exhausted")
			}
			host, _, _ := net.SplitHostPort(man.Config.Listen)
			candidate, err := port.Reserve(ctx, port.Policy{Host: host, First: number + 1, Last: 18543, BlockWebPorts: man.Config.BlockWebPorts})
			if err != nil {
				return err
			}
			man.Config.Listen = candidate.Addr().String()
			_ = candidate.Close()
		}
	}
	return errors.New("automatic port range exhausted")
}

func (m *Manager) stop(ctx context.Context, man Manifest) error {
	if err := m.checkUnits(man); err != nil {
		return err
	}
	args := []string{"stop"}
	for _, p := range []string{m.Layout.socket(), m.Layout.service()} {
		if _, err := os.Lstat(p); err == nil {
			args = append(args, filepath.Base(p))
		}
	}
	if len(args) == 1 {
		return nil
	}
	_, err := m.Runner.Run(ctx, "systemctl", args...)
	return err
}

func (m *Manager) start(ctx context.Context, man Manifest) error {
	if err := m.checkUnits(man); err != nil {
		return err
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "start", "nx-syncd.socket", "nx-syncd.service"); err != nil {
		return err
	}
	host, text, err := net.SplitHostPort(man.Config.Listen)
	if err != nil {
		return err
	}
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	address := net.JoinHostPort(host, text)
	endpoint := "https://" + net.JoinHostPort(man.Config.TLSHost, text)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for {
		result, err := m.Probe(ctx, endpoint, man.Pin, address)
		if err == nil && result.Ready {
			return nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("local pinned HTTPS health check failed; operation remains pending")
		case <-timer.C:
		}
	}
}
