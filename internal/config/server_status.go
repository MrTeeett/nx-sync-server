package config

// ServerUpdates is a non-secret snapshot published by the privileged updater.
// CheckedAt identifies when the configured timer was last verified by the helper.
type ServerUpdates struct {
	Known           bool   `json:"known"`
	Enabled         bool   `json:"enabled"`
	Channel         string `json:"channel"`
	IntervalSeconds int64  `json:"interval_seconds,string"`
	Status          string `json:"status"`
	CheckedAt       string `json:"checked_at"`
}
