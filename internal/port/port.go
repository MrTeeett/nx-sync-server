package port

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
)

type Policy struct {
	Port          int
	Host          string
	BlockWebPorts bool
	First, Last   int
}

func (p Policy) Validate() error {
	if net.ParseIP(p.Host) == nil {
		return errors.New("bind host must be an IP address")
	}
	if p.Port < 0 || p.Port > 65535 {
		return errors.New("port outside 1..65535")
	}
	if p.BlockWebPorts && (p.Port == 80 || p.Port == 443) {
		return errors.New("ports 80/443 are prohibited")
	}
	if p.First == 0 {
		p.First = 18443
	}
	if p.Last == 0 {
		p.Last = 18543
	}
	if p.First < 1024 || p.Last > 65535 || p.First > p.Last || p.Last-p.First > 100 {
		return errors.New("invalid automatic port range")
	}
	return nil
}

// Reserve returns the live listener. The caller owns it and must close or serve
// it, rather than interpreting a socket-table snapshot as a reservation.
func Reserve(ctx context.Context, p Policy) (net.Listener, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.First == 0 {
		p.First = 18443
	}
	if p.Last == 0 {
		p.Last = 18543
	}
	var lc net.ListenConfig
	network := "tcp6"
	if net.ParseIP(p.Host).To4() != nil {
		network = "tcp4"
	}
	if p.Port != 0 {
		return lc.Listen(ctx, network, net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	}
	for candidate := p.First; candidate <= p.Last; candidate++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.BlockWebPorts && (candidate == 80 || candidate == 443) || reserved(candidate) {
			continue
		}
		listener, err := lc.Listen(ctx, network, net.JoinHostPort(p.Host, strconv.Itoa(candidate)))
		if err == nil {
			return listener, nil
		}
	}
	return nil, errors.New("no available port in the configured automatic range")
}

func reserved(port int) bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err == nil {
		parts := strings.Fields(string(data))
		if len(parts) == 2 {
			low, e1 := strconv.Atoi(parts[0])
			high, e2 := strconv.Atoi(parts[1])
			if e1 == nil && e2 == nil && port >= low && port <= high {
				return true
			}
		}
	}
	data, err = os.ReadFile("/proc/sys/net/ipv4/ip_local_reserved_ports")
	if err != nil {
		return false
	}
	for _, part := range strings.Split(strings.TrimSpace(string(data)), ",") {
		bounds := strings.Split(part, "-")
		low, _ := strconv.Atoi(bounds[0])
		high := low
		if len(bounds) == 2 {
			high, _ = strconv.Atoi(bounds[1])
		}
		if low > 0 && port >= low && port <= high {
			return true
		}
	}
	return false
}
