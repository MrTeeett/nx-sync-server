package config

import (
	"errors"
	"net"
	"nx-sync-server/internal/fsutil"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const ProtocolVersion = 1

var Version = "0.1.0-dev"

// Set by the release build so ARM CPU variants cannot be mixed on update.
var BuildTarget string

func Target() string {
	if BuildTarget != "" {
		return BuildTarget
	}
	return "linux-" + runtime.GOARCH
}

type Config struct {
	Version          int    `json:"version"`
	Listen           string `json:"listen"`
	Database         string `json:"database"`
	TLSKey           string `json:"tls_key"`
	TLSCertificate   string `json:"tls_certificate"`
	TLSHost          string `json:"tls_host"`
	MemoryBytes      int64  `json:"memory_bytes"`
	MaxEnvelopeBytes int64  `json:"max_envelope_bytes"`
	MaxProfileBytes  int64  `json:"max_profile_bytes"`
	MaxDevices       int    `json:"max_devices"`
	MaxConnections   int    `json:"max_connections"`
	MaxRequests      int    `json:"max_requests"`
	BlockWebPorts    bool   `json:"block_web_ports"`
}

func Defaults() Config {
	return Config{Version: 1, Listen: "127.0.0.1:18443", MemoryBytes: 256 << 20,
		MaxEnvelopeBytes: 1 << 20, MaxProfileBytes: 64 << 20, MaxDevices: 8,
		MaxConnections: 64, MaxRequests: 16, BlockWebPorts: true}
}

func (c Config) Validate() error {
	if c.Version != 1 {
		return errors.New("unsupported config version")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("listen must be host:port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port || net.ParseIP(host) == nil {
		return errors.New("listen requires an IP and canonical numeric TCP port")
	}
	if c.BlockWebPorts && (number == 80 || number == 443) {
		return errors.New("ports 80/443 are prohibited by installation policy")
	}
	if c.MemoryBytes < 64<<20 || c.MemoryBytes > 1<<40 {
		return errors.New("invalid memory budget")
	}
	if c.MaxEnvelopeBytes < 1 || c.MaxEnvelopeBytes > 1<<20 || c.MaxProfileBytes < c.MaxEnvelopeBytes || c.MaxProfileBytes > 1<<30 {
		return errors.New("invalid storage budget")
	}
	if c.MaxDevices < 1 || c.MaxDevices > 64 || c.MaxConnections < 1 || c.MaxConnections > 10000 || c.MaxRequests < 1 || c.MaxRequests > c.MaxConnections {
		return errors.New("invalid concurrency budget")
	}
	for _, p := range []string{c.Database, c.TLSKey, c.TLSCertificate} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("config paths must be clean absolute paths")
		}
	}
	if c.TLSHost == "" || strings.ContainsAny(c.TLSHost, "/*:\\ \t\r\n") && net.ParseIP(c.TLSHost) == nil {
		return errors.New("TLS host must be an IP or DNS name")
	}
	return nil
}

func Load(path string) (Config, error) {
	var c Config
	if err := fsutil.ReadJSON(path, &c, 64<<10); err != nil {
		return c, err
	}
	return c, c.Validate()
}
