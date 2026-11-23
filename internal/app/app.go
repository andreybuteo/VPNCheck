// Package app holds application-wide constants: name, version, data paths and
// the conservative network limits that every other package must respect.
package app

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"vpncheck/internal/i18n"
)

// Name is the human-readable application name.
const Name = "VPN Check"

// DirName is the folder name under %LOCALAPPDATA%.
const DirName = "VPNCheck"

// Version is overridden at build time via -ldflags "-X vpncheck/internal/app.Version=...".
// Versioning rule: a major change adds 1.0, any other change adds 0.1
// (see README, «Версионирование»). Keep winres/winres.json in sync.
var Version = "4.5"

// Limits that the backend enforces regardless of UI state (spec §7).
const (
	// MaxConcurrentProbes is the global cap on simultaneous probes.
	MaxConcurrentProbes = 4
	// GroupStartSpacing is the minimum spacing between probe starts inside one service group.
	GroupStartSpacing = 1 * time.Second
	// RunCooldown is the default pause between two run starts; the user can
	// change it in settings within [MinRunCooldown, MaxRunCooldown].
	RunCooldown = 60 * time.Second
	// MinRunCooldown and MaxRunCooldown bound the user-set pause between runs.
	MinRunCooldown = 10 * time.Second
	MaxRunCooldown = 30 * time.Minute
	// HostHourlyCap is disabled (0) so route changes can be tested repeatedly.
	HostHourlyCap = 0
	// HostWindow is the sliding window for HostHourlyCap.
	HostWindow = time.Hour
	// ProbeTimeout is the total deadline of one probe.
	ProbeTimeout = 10 * time.Second
	// TCPTimeout is the maximum time for the TCP connect phase (within ProbeTimeout).
	TCPTimeout = 4 * time.Second
	// TLSTimeout is the maximum time for the TLS handshake phase (within ProbeTimeout).
	TLSTimeout = 4 * time.Second
	// MaxBodyBytes is the maximum HTTP body read by the application.
	MaxBodyBytes = 64 * 1024
	// MaxHeaderBytes is the maximum size of response headers.
	MaxHeaderBytes = 32 * 1024
	// RateLimitDefaultBlock is used for HTTP 429 when no Retry-After information is present.
	RateLimitDefaultBlock = 15 * time.Minute
	// StabilityProbes is the number of probes per endpoint in stability mode.
	StabilityProbes = 3
	// StabilityMaxEndpoints is the maximum number of endpoints in stability mode.
	StabilityMaxEndpoints = 5
	// StabilityInterval is the minimum interval between probes of the same endpoint.
	StabilityInterval = 10 * time.Second
	// HistoryLimit is the number of runs kept in history.
	HistoryLimit = 100
)

// Speed test limits (3.0). They keep the load close to one person pressing
// "start" on a public speed-test page now and then, never a background load.
const (
	// SpeedCooldown is the minimum time between two speed-test starts.
	SpeedCooldown = 3 * time.Minute
	// SpeedDailyCap is the maximum number of speed tests in any 24 hours.
	SpeedDailyCap = 20
	// SpeedPhase is the length of the download and of the upload phase.
	SpeedPhase = 8 * time.Second
	// SpeedWarmup is excluded from the throughput figure (TCP slow start).
	SpeedWarmup = 1500 * time.Millisecond
	// SpeedParallel is the number of parallel HTTP/1.1 connections per phase.
	SpeedParallel = 4
	// SpeedDownCap and SpeedUpCap stop a phase early once this much has moved.
	SpeedDownCap = 150 << 20
	SpeedUpCap   = 50 << 20
	// SpeedLatencySamples is the number of empty requests for latency.
	SpeedLatencySamples = 10
	// SpeedBlockDefault pauses a speed server after 429/403/challenge without Retry-After.
	SpeedBlockDefault = time.Hour
	// SpeedHistoryLimit is the number of speed results kept.
	SpeedHistoryLimit = 100
)

// DataDir returns the per-user data directory (%LOCALAPPDATA%\VPNCheck).
// If override is non-empty it is used instead. The directory is created.
func DataDir(override string) (string, error) {
	dir := override
	if dir == "" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			var err error
			base, err = os.UserCacheDir()
			if err != nil {
				return "", errors.New(i18n.T("не удалось определить %LOCALAPPDATA%: ") + err.Error())
			}
		}
		dir = filepath.Join(base, DirName)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}
