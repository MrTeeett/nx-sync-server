package host

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type runFunc func(context.Context, string, ...string) ([]byte, error)

func (f runFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

func TestFirewalldKeepsPreexistingRules(t *testing.T) {
	var calls []string
	r := runFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		return []byte("yes"), nil
	})
	rule, err := PlanRule(context.Background(), r, "firewalld", "public", "installation", 18443)
	if err != nil {
		t.Fatal(err)
	}
	if rule.RuntimeOwned || rule.PermanentOwned {
		t.Fatal("pre-existing opening acquired ownership")
	}
	if err = ApplyRule(context.Background(), r, &rule); err != nil {
		t.Fatal(err)
	}
	if err = RemoveRule(context.Background(), r, rule); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("unexpected firewall mutation: %v", calls)
	}
}

func TestUFWOwningMarkerAndUnrelatedRules(t *testing.T) {
	state := "ufw allow 22/tcp\n"
	var calls []string
	r := runFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if strings.Contains(call, "show added") {
			return []byte(state), nil
		}
		if args[0] == "allow" {
			state += "ufw allow in proto tcp to any port 18443 comment 'nx-sync:owned'\n"
			return nil, nil
		}
		if strings.Contains(call, "--force delete allow") {
			state = "ufw allow 22/tcp\nufw allow 443/tcp\n"
			return nil, nil
		}
		return nil, errors.New("unexpected command")
	})
	rule, err := PlanRule(context.Background(), r, "ufw", "", "owned", 18443)
	if err != nil {
		t.Fatal(err)
	}
	if err = ApplyRule(context.Background(), r, &rule); err != nil {
		t.Fatal(err)
	}
	state += "ufw allow 443/tcp\n"
	if err = RemoveRule(context.Background(), r, rule); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state, "443") || strings.Contains(state, "nx-sync:") {
		t.Fatalf("wrong cleanup: %s", state)
	}
	for _, call := range calls {
		if strings.Contains(call, "reset") || strings.Contains(call, "enable") || strings.Contains(call, "reload") {
			t.Fatalf("global mutation: %s", call)
		}
	}
}

func TestUnknownFirewallDoesNotPretendToBeUnfiltered(t *testing.T) {
	r := runFunc(func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("no inspection tools")
	})
	provider, err := DetectFirewall(context.Background(), r)
	if err != nil || provider != "manual" {
		t.Fatalf("provider=%s err=%v", provider, err)
	}
}
