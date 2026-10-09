package host

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"nx-sync-server/internal/port"
	"nx-sync-server/internal/release"
)

func CheckSystem(memory int64) error {
	if runtime.GOOS != "linux" {
		return errors.New("automatic installation requires Linux")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("automatic installation requires systemd; OpenWrt installation is not supported")
	}
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil || !strings.Contains(" "+strings.TrimSpace(string(controllers))+" ", " memory ") {
		return errors.New("cgroup v2 memory controller required")
	}
	if memory < 64<<20 || memory > 1<<40 {
		return errors.New("invalid daemon memory budget")
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return err
	}
	var total, available int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = value * 1024
		case "MemAvailable:":
			available = value * 1024
		}
	}
	if total < memory+128<<20 || available < memory+64<<20 {
		return errors.New("insufficient memory reserve for the OS and existing services; choose a smaller daemon budget")
	}
	return nil
}

type Preflight struct {
	Listen               string `json:"proposed_listen"`
	Firewall             string `json:"firewall"`
	FinalBind            string `json:"final_bind"`
	ExternalReachability string `json:"external_reachability"`
	Unsigned             bool   `json:"unsigned"`
	Version              string `json:"version"`
	Channel              string `json:"channel"`
}

// Preflight is read-only. A preview listener is closed and is not a promise
// that a later install can bind the same port.
func (m *Manager) Preflight(ctx context.Context, o InstallOptions) (Preflight, error) {
	verified, err := release.Inspect(filepath.Join(o.Bundle, "release.json"), o.TrustKey, 0, time.Now(), o.AllowUnsigned)
	if err != nil {
		return Preflight{}, err
	}
	if err = release.CheckArtifacts(o.Bundle, verified.Metadata); err != nil {
		return Preflight{}, err
	}
	if err := m.checkFresh(ctx); err != nil {
		return Preflight{}, err
	}
	l, err := port.Reserve(ctx, port.Policy{Host: o.Bind, Port: o.Port, BlockWebPorts: o.BlockWebPorts})
	if err != nil {
		return Preflight{}, err
	}
	address := l.Addr().(*net.TCPAddr).String()
	_ = l.Close()
	firewall, err := DetectFirewall(ctx, m.Runner)
	if err != nil {
		return Preflight{}, err
	}
	return Preflight{Listen: address, Firewall: firewall, FinalBind: "systemd_socket_during_install", ExternalReachability: "check_from_client", Unsigned: !verified.Signed, Version: verified.Metadata.Version, Channel: verified.Metadata.Channel}, nil
}
