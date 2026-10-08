package port

import (
	"context"
	"net"
	"testing"
)

func TestManualPortExclusivityAndWebPolicy(t *testing.T) {
	for _, number := range []int{80, 443} {
		if _, err := Reserve(context.Background(), Policy{Host: "127.0.0.1", Port: number, BlockWebPorts: true}); err == nil {
			t.Fatalf("reserved web port %d", number)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	number := l.Addr().(*net.TCPAddr).Port
	if _, err = Reserve(context.Background(), Policy{Host: "127.0.0.1", Port: number}); err == nil {
		t.Fatal("manual busy port was silently replaced")
	}
}

func TestAutoReserveHoldsListener(t *testing.T) {
	l, err := Reserve(context.Background(), Policy{Host: "127.0.0.1", BlockWebPorts: true})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if second, err := net.Listen("tcp", l.Addr().String()); err == nil {
		_ = second.Close()
		t.Fatal("reservation did not hold the port")
	}
}

func TestIPv4WildcardPreservesFamily(t *testing.T) {
	l, err := Reserve(context.Background(), Policy{Host: "0.0.0.0", BlockWebPorts: true})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if address := l.Addr().(*net.TCPAddr); address.IP.To4() == nil {
		t.Fatalf("IPv4 bind was silently converted to IPv6: %s", address)
	}
}
