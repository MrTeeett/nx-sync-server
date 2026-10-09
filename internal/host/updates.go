package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nx-sync-server/internal/config"
	"nx-sync-server/internal/fsutil"
	"nx-sync-server/internal/release"
	"nx-sync-server/internal/updates"
)

type UpdatePolicy struct {
	Format              int    `json:"format"`
	InstallationID      string `json:"installation_id"`
	Enabled             bool   `json:"enabled"`
	Channel             string `json:"channel"`
	IntervalSeconds     int64  `json:"interval_seconds"`
	AllowUnsigned       bool   `json:"allow_unsigned"`
	ServiceHash         string `json:"service_hash,omitempty"`
	TimerHash           string `json:"timer_hash,omitempty"`
	PreviousServiceHash string `json:"previous_service_hash,omitempty"`
	PreviousTimerHash   string `json:"previous_timer_hash,omitempty"`
}

type OnlineResult struct {
	Updated      bool     `json:"updated"`
	Installation Manifest `json:"installation"`
	Channel      string   `json:"channel"`
}

type UpdateState struct {
	InstallationID  string `json:"installation_id"`
	Channel         string `json:"channel"`
	Digest          string `json:"digest"`
	HighestSequence uint64 `json:"highest_sequence,string"`
	CheckedAt       string `json:"checked_at"`
}

func (m *Manager) updatePolicyPath() string {
	return filepath.Join(m.Layout.meta(), "update-policy.json")
}
func (m *Manager) updateServicePath() string {
	return m.Layout.path("/etc/systemd/system/nx-sync-update.service")
}
func (m *Manager) updateTimerPath() string {
	return m.Layout.path("/etc/systemd/system/nx-sync-update.timer")
}

func (p UpdatePolicy) validate() error {
	if p.Format != 1 || p.Channel != "stable" && p.Channel != "dev" || p.IntervalSeconds < 3600 || p.IntervalSeconds > 30*24*3600 {
		return errors.New("update interval must be 1 hour to 30 days and channel stable or dev")
	}
	return nil
}

func (m *Manager) UpdatePolicy() (UpdatePolicy, error) {
	man, err := m.load()
	if err != nil {
		return UpdatePolicy{}, err
	}
	p := UpdatePolicy{Format: 1, InstallationID: man.InstallationID, Channel: "stable", IntervalSeconds: 86400}
	if err = fsutil.ReadJSON(m.updatePolicyPath(), &p, 64<<10); errors.Is(err, os.ErrNotExist) {
		return p, nil
	} else if err != nil {
		return p, err
	}
	if p.InstallationID != man.InstallationID {
		return p, errors.New("update policy belongs to another installation")
	}
	return p, p.validate()
}

func (m *Manager) verifyUpdateUnits(p UpdatePolicy) error {
	for _, path := range []string{m.updateServicePath(), m.updateTimerPath()} {
		if _, err := os.Lstat(path + ".d"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("untracked update service drop-in")
		}
	}
	if err := verifyOwnedFile(m.updateServicePath(), p.ServiceHash, p.PreviousServiceHash); err != nil {
		return err
	}
	return verifyOwnedFile(m.updateTimerPath(), p.TimerHash, p.PreviousTimerHash)
}

func (m *Manager) ConfigureUpdates(ctx context.Context, next UpdatePolicy) (UpdatePolicy, error) {
	unlock, err := m.lock()
	if err != nil {
		return UpdatePolicy{}, err
	}
	defer unlock()
	man, err := m.checkIdle()
	if err != nil {
		return UpdatePolicy{}, err
	}
	previous, err := m.UpdatePolicy()
	if err != nil {
		return previous, err
	}
	if err = m.verifyUpdateUnits(previous); err != nil {
		return previous, err
	}
	if previous.ServiceHash == "" {
		for _, unit := range []string{"nx-sync-update.service", "nx-sync-update.timer"} {
			data, inspectErr := m.Runner.Run(ctx, "systemctl", "show", unit, "--property=LoadState", "--value")
			if inspectErr != nil && status(inspectErr) != 4 {
				return previous, inspectErr
			}
			if value := strings.TrimSpace(string(data)); value != "" && value != "not-found" {
				return previous, errors.New("foreign update unit already exists")
			}
		}
	}
	next.Format = 1
	next.InstallationID = man.InstallationID
	if err = next.validate(); err != nil {
		return previous, err
	}
	path := strconv.Quote(strings.ReplaceAll(filepath.Join(m.Layout.app(), "current", "nx-syncctl"), "%", "%%"))
	service := fmt.Sprintf(`[Unit]
Description=NX sync server update check (%s)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s auto-update
TimeoutStartSec=10min
UMask=0077
MemoryMax=536870912
MemoryHigh=402653184
MemorySwapMax=0
TasksMax=64
Environment=GOMEMLIMIT=201326592
Nice=10
CPUWeight=20
IOWeight=20
`, man.InstallationID, path)
	timer := fmt.Sprintf(`[Unit]
Description=NX sync server update schedule (%s)

[Timer]
OnActiveSec=5min
OnUnitInactiveSec=%ds
RandomizedDelaySec=5min
Unit=nx-sync-update.service

[Install]
WantedBy=timers.target
`, man.InstallationID, next.IntervalSeconds)
	next.PreviousServiceHash = ""
	next.PreviousTimerHash = ""
	for _, current := range []struct {
		path string
		hash *string
	}{{m.updateServicePath(), &next.PreviousServiceHash}, {m.updateTimerPath(), &next.PreviousTimerHash}} {
		data, readErr := readRegular(current.path, 128<<10)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return previous, readErr
		}
		if readErr == nil {
			*current.hash = digest(data)
		}
	}
	next.ServiceHash = digest([]byte(service))
	next.TimerHash = digest([]byte(timer))
	if err = fsutil.WriteJSON(m.updatePolicyPath(), next, 0600); err != nil {
		return previous, err
	}
	if err = fsutil.AtomicWrite(m.updateServicePath(), []byte(service), 0644); err != nil {
		return next, err
	}
	if err = fsutil.AtomicWrite(m.updateTimerPath(), []byte(timer), 0644); err != nil {
		return next, err
	}
	if _, err = m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return next, err
	}
	if next.Enabled {
		_, err = m.Runner.Run(ctx, "systemctl", "enable", "--now", "nx-sync-update.timer")
		if err == nil {
			_, err = m.Runner.Run(ctx, "systemctl", "restart", "nx-sync-update.timer")
		}
	} else {
		_, err = m.Runner.Run(ctx, "systemctl", "disable", "--now", "nx-sync-update.timer")
	}
	if err != nil {
		return next, err
	}
	next.PreviousServiceHash = ""
	next.PreviousTimerHash = ""
	return next, fsutil.WriteJSON(m.updatePolicyPath(), next, 0600)
}

func (m *Manager) removeUpdateUnits(ctx context.Context, man Manifest) error {
	p, err := m.UpdatePolicy()
	if err != nil {
		return err
	}
	if err = m.verifyUpdateUnits(p); err != nil {
		return err
	}
	if p.ServiceHash == "" && p.TimerHash == "" {
		return nil
	}
	if _, err = m.Runner.Run(ctx, "systemctl", "disable", "--now", "nx-sync-update.timer"); err != nil {
		return err
	}
	// Do not stop the updater process that currently holds the administration
	// lock. It cannot run concurrently with this uninstall operation.
	for _, path := range []string{m.updateServicePath(), m.updateTimerPath(), m.updatePolicyPath()} {
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m *Manager) UpdateOnline(ctx context.Context, channel string, allowUnsigned bool) (OnlineResult, error) {
	return m.updateOnline(ctx, channel, allowUnsigned, nil)
}

func (m *Manager) updateOnline(ctx context.Context, channel string, allowUnsigned bool, expected *UpdatePolicy) (OnlineResult, error) {
	man, op, err := m.Status()
	result := OnlineResult{Installation: man, Channel: channel}
	if err != nil {
		return result, err
	}
	if op.Stage != "complete" || man.State != "installed" {
		return result, errors.New("pending operation must be recovered before fetching an update")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	client := updates.New()
	candidate, err := client.Latest(ctx, channel, config.Target())
	if err != nil {
		return result, err
	}
	if channel == "stable" && updates.IsStableDowngrade(candidate.Tag, man.Version) {
		return result, errors.New("latest stable release is older than the installed version; use explicit compatible rollback instead")
	}
	statePath := filepath.Join(m.Layout.meta(), "update-state.json")
	var state UpdateState
	if stateErr := fsutil.ReadJSON(statePath, &state, 64<<10); stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return result, stateErr
	}
	if candidate.Archive.Digest != "" && state.InstallationID == man.InstallationID && state.Channel == channel && state.Digest == candidate.Archive.Digest && state.HighestSequence == man.HighestSequence {
		state.CheckedAt = time.Now().UTC().Format(time.RFC3339)
		return result, fsutil.WriteJSON(statePath, state, 0600)
	}
	if channel == "stable" && strings.TrimPrefix(candidate.Tag, "v") == man.Version {
		return result, nil
	}
	if err = secureDirectory(m.Layout.meta(), os.Geteuid(), os.Getegid(), 0700); err != nil {
		return result, err
	}
	bundle, err := client.Download(ctx, candidate, m.Layout.meta())
	if err != nil {
		return result, err
	}
	defer func() {
		_, operation, inspectErr := m.Status()
		if inspectErr == nil && operation.Stage == "complete" {
			_ = os.RemoveAll(bundle)
		}
	}()
	verified, err := release.Inspect(filepath.Join(bundle, "release.json"), man.TrustKey, 0, time.Now(), allowUnsigned)
	if err != nil {
		return result, err
	}
	if verified.Metadata.Channel != channel {
		return result, errors.New("package channel differs from selected update channel")
	}
	if channel == "stable" && verified.Metadata.Version != strings.TrimPrefix(candidate.Tag, "v") {
		return result, errors.New("stable package version differs from its GitHub release tag")
	}
	if err = release.CheckArtifacts(bundle, verified.Metadata); err != nil {
		return result, err
	}
	if verified.Metadata.Sequence <= man.HighestSequence {
		state = UpdateState{InstallationID: man.InstallationID, Channel: channel, Digest: candidate.Archive.Digest, HighestSequence: man.HighestSequence, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		return result, fsutil.WriteJSON(statePath, state, 0600)
	}
	result.Installation, err = m.UpdateWithOptions(ctx, UpdateOptions{Bundle: bundle, AllowUnsigned: allowUnsigned, RollbackOnFailure: true, ExpectedPolicy: expected})
	result.Updated = err == nil
	if err == nil {
		state = UpdateState{InstallationID: man.InstallationID, Channel: channel, Digest: candidate.Archive.Digest, HighestSequence: result.Installation.HighestSequence, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		err = fsutil.WriteJSON(statePath, state, 0600)
	}
	return result, err
}

func (m *Manager) AutoUpdate(ctx context.Context) (OnlineResult, error) {
	p, err := m.UpdatePolicy()
	if err != nil {
		return OnlineResult{}, err
	}
	if !p.Enabled {
		return OnlineResult{Channel: p.Channel}, nil
	}
	if err = m.verifyUpdateUnits(p); err != nil {
		return OnlineResult{}, err
	}
	return m.updateOnline(ctx, p.Channel, p.AllowUnsigned, &p)
}
