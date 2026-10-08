package host

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Rule struct {
	Provider       string `json:"provider"`
	Zone           string `json:"zone,omitempty"`
	Port           int    `json:"port"`
	Marker         string `json:"marker,omitempty"`
	RuntimeOwned   bool   `json:"runtime_owned"`
	PermanentOwned bool   `json:"permanent_owned"`
	Before         string `json:"before,omitempty"`
	After          string `json:"after,omitempty"`
}

func DetectFirewall(ctx context.Context, r Runner) (string, error) {
	firewalld, ufw := false, false
	if _, err := r.Run(ctx, "firewall-cmd", "--state"); err == nil {
		firewalld = true
	}
	if output, err := r.Run(ctx, "ufw", "status"); err == nil && strings.Contains(string(output), "Status: active") {
		ufw = true
	}
	if firewalld && ufw {
		return "", errors.New("multiple active firewall managers")
	}
	if firewalld {
		return "firewalld", nil
	}
	if ufw {
		return "ufw", nil
	}
	inspected := false
	if output, err := r.Run(ctx, "nft", "list", "ruleset"); err == nil {
		inspected = true
		if strings.TrimSpace(string(output)) != "" {
			return "manual", nil
		}
	}
	if output, err := r.Run(ctx, "iptables", "-S"); err == nil {
		inspected = true
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			if strings.HasPrefix(line, "-A ") || strings.Contains(line, " DROP") || strings.Contains(line, " REJECT") {
				return "manual", nil
			}
		}
	}
	if inspected {
		return "none", nil
	}
	return "manual", nil
}

func PlanRule(ctx context.Context, r Runner, provider, zone, installation string, port int) (Rule, error) {
	rule := Rule{Provider: provider, Zone: zone, Port: port, Marker: "nx-sync:" + installation}
	if provider == "firewalld" {
		if zone == "" {
			output, err := r.Run(ctx, "firewall-cmd", "--get-active-zones")
			if err != nil {
				return rule, err
			}
			zones := []string{}
			for _, line := range strings.Split(string(output), "\n") {
				if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
					zones = append(zones, strings.TrimSpace(line))
				}
			}
			if len(zones) != 1 {
				return rule, errors.New("explicit ingress firewalld zone required")
			}
			zone = zones[0]
			rule.Zone = zone
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(zone) {
			return rule, errors.New("invalid firewall zone")
		}
		for _, permanent := range []bool{false, true} {
			args := []string{"--zone=" + zone, "--query-port=" + strconv.Itoa(port) + "/tcp"}
			if permanent {
				args = append([]string{"--permanent"}, args...)
			}
			_, err := r.Run(ctx, "firewall-cmd", args...)
			if err != nil && status(err) != 1 {
				return rule, err
			}
			if permanent {
				rule.PermanentOwned = err != nil
			} else {
				rule.RuntimeOwned = err != nil
			}
		}
	} else if provider == "ufw" {
		output, err := r.Run(ctx, "ufw", "show", "added")
		if err != nil {
			return rule, err
		}
		// Conservatively reuse any existing rule mentioning the port; never replace
		// its comment. External reachability is verified separately.
		mentioned := regexp.MustCompile(fmt.Sprintf(`(^|[^0-9])%d([^0-9]|$)`, port)).Match(output)
		rule.RuntimeOwned = !mentioned
		rule.PermanentOwned = !mentioned
	} else if provider != "none" && provider != "manual" {
		return rule, errors.New("unsupported firewall manager")
	}
	return rule, nil
}

func ApplyRule(ctx context.Context, r Runner, rule *Rule) error {
	if rule.Provider == "firewalld" {
		for _, permanent := range []bool{false, true} {
			owned := rule.RuntimeOwned
			if permanent {
				owned = rule.PermanentOwned
			}
			if !owned {
				continue
			}
			args := []string{"--zone=" + rule.Zone, "--add-port=" + strconv.Itoa(rule.Port) + "/tcp"}
			if permanent {
				args = append([]string{"--permanent"}, args...)
			}
			if _, err := r.Run(ctx, "firewall-cmd", args...); err != nil {
				return err
			}
			args[len(args)-1] = "--query-port=" + strconv.Itoa(rule.Port) + "/tcp"
			if _, err := r.Run(ctx, "firewall-cmd", args...); err != nil {
				return err
			}
		}
	} else if rule.Provider == "ufw" && rule.RuntimeOwned {
		if _, err := r.Run(ctx, "ufw", "allow", "in", "proto", "tcp", "to", "any", "port", strconv.Itoa(rule.Port), "comment", rule.Marker); err != nil {
			return err
		}
		output, err := r.Run(ctx, "ufw", "show", "added")
		if err != nil {
			return err
		}
		if !strings.Contains(string(output), rule.Marker) {
			return errors.New("UFW marker was not persisted")
		}
		rule.After = markerLines(string(output), rule.Marker)
	}
	return nil
}

func RemoveRule(ctx context.Context, r Runner, rule Rule) error {
	if rule.Provider == "firewalld" {
		for _, permanent := range []bool{false, true} {
			owned := rule.RuntimeOwned
			if permanent {
				owned = rule.PermanentOwned
			}
			if !owned {
				continue
			}
			args := []string{"--zone=" + rule.Zone, "--query-port=" + strconv.Itoa(rule.Port) + "/tcp"}
			if permanent {
				args = append([]string{"--permanent"}, args...)
			}
			if _, err := r.Run(ctx, "firewall-cmd", args...); status(err) == 1 {
				continue
			} else if err != nil {
				return err
			}
			args[len(args)-1] = "--remove-port=" + strconv.Itoa(rule.Port) + "/tcp"
			if _, err := r.Run(ctx, "firewall-cmd", args...); err != nil {
				return err
			}
		}
	} else if rule.Provider == "ufw" && rule.RuntimeOwned {
		output, err := r.Run(ctx, "ufw", "show", "added")
		if err != nil {
			return err
		}
		if !strings.Contains(string(output), rule.Marker) {
			return nil
		}
		if rule.After == "" || markerLines(string(output), rule.Marker) != rule.After {
			return errors.New("UFW configuration changed; ownership must be reviewed before removal")
		}
		_, err = r.Run(ctx, "ufw", "--force", "delete", "allow", "in", "proto", "tcp", "to", "any", "port", strconv.Itoa(rule.Port), "comment", rule.Marker)
		return err
	}
	return nil
}

// Compare only the owned UFW rule. Unrelated administrator additions must
// survive cleanup and must not prevent deleting the unchanged owned rule.
func markerLines(output, marker string) string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, marker) {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}
