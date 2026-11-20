// Package limiter enforces the conservative behaviour of spec §7 inside the
// backend: global and per-host concurrency, start spacing inside a service
// group, a single active run, a cooldown between runs, a sliding per-host
// hourly cap, and blocks after 403/CAPTCHA (for the run) and 429 (persisted,
// honouring Retry-After). Limits survive a normal restart via limiter.json and
// are never reset by switching the VPN profile.
package limiter

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
	"vpncheck/internal/store"
)

const fileName = "limiter.json"

// ErrRunActive is returned when a run is already in progress.
var ErrRunActive = errors.New("проверка уже выполняется")

// CooldownError reports how long to wait before the next run may start.
type CooldownError struct {
	Wait  time.Duration
	Until time.Time
}

func (e *CooldownError) Error() string {
	return i18n.T("cooldown: следующий запуск возможен через ") + e.Wait.Round(time.Second).String()
}

// Block is a persisted per-host block (HTTP 429).
type Block struct {
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
	Status int       `json:"status"`
}

// State is the persisted part of the limiter.
type State struct {
	SchemaVersion int                    `json:"schemaVersion"`
	LastRunStart  *time.Time             `json:"lastRunStart"`
	HostProbes    map[string][]time.Time `json:"hostProbes"`
	HostBlocks    map[string]Block       `json:"hostBlocks"`
	// Speed test (3.0): last start, starts in the last 24 h, paused servers.
	LastSpeedStart *time.Time       `json:"lastSpeedStart,omitempty"`
	SpeedStarts    []time.Time      `json:"speedStarts,omitempty"`
	SpeedBlocks    map[string]Block `json:"speedBlocks,omitempty"`
}

// Allowance is the answer to "may this host be probed now?".
type Allowance struct {
	OK     bool
	Code   string // "run_block_403", "run_block_captcha", "rate_limited_429", "hourly_cap"
	Reason string
	Until  time.Time
}

// Limiter is safe for concurrent use.
type Limiter struct {
	mu    sync.Mutex
	st    *store.Store
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
	state State

	// Tunables (defaults from package app); tests lower them.
	MaxConcurrent int
	GroupSpacing  time.Duration
	RunCooldown   time.Duration
	HostCap       int
	HostWindow    time.Duration
	DefaultBlock  time.Duration
	SpeedCooldown time.Duration
	SpeedDailyCap int

	sem         chan struct{}
	hostBusy    map[string]bool
	groupSlot   map[string]time.Time
	runActive   bool
	runBlocked  map[string]Allowance
	speedActive bool
}

// New loads persisted state (if any). st may be nil for in-memory use.
func New(st *store.Store, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	l := &Limiter{
		st:            st,
		now:           now,
		MaxConcurrent: app.MaxConcurrentProbes,
		GroupSpacing:  app.GroupStartSpacing,
		RunCooldown:   app.RunCooldown,
		HostCap:       app.HostHourlyCap,
		HostWindow:    app.HostWindow,
		DefaultBlock:  app.RateLimitDefaultBlock,
		SpeedCooldown: app.SpeedCooldown,
		SpeedDailyCap: app.SpeedDailyCap,
		hostBusy:      map[string]bool{},
		groupSlot:     map[string]time.Time{},
		runBlocked:    map[string]Allowance{},
		state:         State{SchemaVersion: model.SchemaVersion, HostProbes: map[string][]time.Time{}, HostBlocks: map[string]Block{}},
	}
	l.sleep = func(ctx context.Context, d time.Duration) error {
		if d <= 0 {
			return ctx.Err()
		}
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	l.sem = make(chan struct{}, l.MaxConcurrent)
	if st != nil {
		var s State
		if info, err := st.LoadJSON(fileName, &s); err == nil && info.Found && !info.Corrupt {
			if s.HostProbes == nil {
				s.HostProbes = map[string][]time.Time{}
			}
			if s.HostBlocks == nil {
				s.HostBlocks = map[string]Block{}
			}
			s.SchemaVersion = model.SchemaVersion
			l.state = s
		}
	}
	l.pruneLocked()
	return l
}

// SetSleep overrides waiting (tests).
func (l *Limiter) SetSleep(f func(context.Context, time.Duration) error) { l.sleep = f }

// resize must be called after changing MaxConcurrent in tests.
func (l *Limiter) Resize() { l.sem = make(chan struct{}, l.MaxConcurrent) }

func (l *Limiter) persistLocked() {
	if l.st == nil {
		return
	}
	_ = l.st.SaveJSON(fileName, l.state)
}

func (l *Limiter) pruneLocked() {
	now := l.now()
	if l.HostCap <= 0 {
		l.state.HostProbes = map[string][]time.Time{}
	}
	for h, ts := range l.state.HostProbes {
		keep := ts[:0]
		for _, t := range ts {
			if now.Sub(t) < l.HostWindow {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(l.state.HostProbes, h)
		} else {
			l.state.HostProbes[h] = keep
		}
	}
	for h, b := range l.state.HostBlocks {
		if !b.Until.After(now) {
			delete(l.state.HostBlocks, h)
		}
	}
	keep := l.state.SpeedStarts[:0]
	for _, t := range l.state.SpeedStarts {
		if now.Sub(t) < 24*time.Hour {
			keep = append(keep, t)
		}
	}
	l.state.SpeedStarts = keep
	for h, b := range l.state.SpeedBlocks {
		if !b.Until.After(now) {
			delete(l.state.SpeedBlocks, h)
		}
	}
}

// StartRun claims the single run slot, enforcing the cooldown measured from the
// start of the previous run. The claim is persisted immediately.
func (l *Limiter) StartRun() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runActive {
		return ErrRunActive
	}
	if l.speedActive {
		return ErrSpeedActive
	}
	now := l.now()
	if l.state.LastRunStart != nil {
		if until := l.state.LastRunStart.Add(l.RunCooldown); until.After(now) {
			return &CooldownError{Wait: until.Sub(now), Until: until}
		}
	}
	t := now
	l.state.LastRunStart = &t
	l.runActive = true
	l.runBlocked = map[string]Allowance{}
	l.groupSlot = map[string]time.Time{}
	l.persistLocked()
	return nil
}

// SetRunCooldown changes the pause between run starts. It applies at once,
// also to the pause already counting from the previous run.
func (l *Limiter) SetRunCooldown(d time.Duration) {
	l.mu.Lock()
	l.RunCooldown = d
	l.mu.Unlock()
}

// Cooldown returns the current pause between run starts.
func (l *Limiter) Cooldown() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.RunCooldown
}

// CooldownUntil returns when the next run may start (zero if now).
func (l *Limiter) CooldownUntil() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state.LastRunStart == nil {
		return time.Time{}
	}
	until := l.state.LastRunStart.Add(l.RunCooldown)
	if until.After(l.now()) {
		return until
	}
	return time.Time{}
}

// RunActive reports whether a run holds the slot.
func (l *Limiter) RunActive() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.runActive
}

// EndRun releases the run slot. Per-run blocks (403/CAPTCHA) are dropped;
// persisted 429 blocks and the hourly window are kept.
func (l *Limiter) EndRun() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.runActive = false
	l.runBlocked = map[string]Allowance{}
	l.groupSlot = map[string]time.Time{}
}

// Allowance answers whether host may be probed now and, if not, why and until when.
func (l *Limiter) Allowance(host string) Allowance { return l.AllowanceScoped(host, "") }

// AllowanceScoped is Allowance where the per-run 403/CAPTCHA block is keyed by
// host+scope (diag mode uses the route as scope, so the alternative route
// still gets its single probe). Persisted blocks and the hourly cap stay per host.
func (l *Limiter) AllowanceScoped(host, scope string) Allowance {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allowanceLocked(strings.ToLower(host), scope)
}

func (l *Limiter) allowanceLocked(host, scope string) Allowance {
	l.pruneLocked()
	if a, ok := l.runBlocked[host+"|"+scope]; ok {
		return a
	}
	if b, ok := l.state.HostBlocks[host]; ok {
		return Allowance{Code: "rate_limited_429", Reason: b.Reason, Until: b.Until}
	}
	ts := l.state.HostProbes[host]
	if l.HostCap > 0 && len(ts) >= l.HostCap {
		sorted := append([]time.Time(nil), ts...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })
		until := sorted[len(sorted)-l.HostCap].Add(l.HostWindow)
		return Allowance{Code: "hourly_cap", Reason: i18n.T("достигнут локальный потолок 12 проб в час для этого хоста"), Until: until}
	}
	return Allowance{OK: true}
}

// Acquire waits for a probe slot for host inside group: global concurrency,
// one in-flight probe per host, and start spacing within the group. On success
// the probe start is recorded in the hourly window and persisted. The returned
// release function must be called when the probe finishes.
func (l *Limiter) Acquire(ctx context.Context, host, group string) (release func(), err error) {
	host = strings.ToLower(host)
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	releaseSem := func() { <-l.sem }

	// Wait until no other probe of this host is in flight.
	for {
		l.mu.Lock()
		if !l.hostBusy[host] {
			l.hostBusy[host] = true
			l.mu.Unlock()
			break
		}
		l.mu.Unlock()
		if err := l.sleep(ctx, 25*time.Millisecond); err != nil {
			releaseSem()
			return nil, err
		}
	}
	releaseHost := func() {
		l.mu.Lock()
		delete(l.hostBusy, host)
		l.mu.Unlock()
	}

	// Book the next start slot for the group.
	l.mu.Lock()
	now := l.now()
	slot := now
	if last, ok := l.groupSlot[group]; ok && last.Add(l.GroupSpacing).After(slot) {
		slot = last.Add(l.GroupSpacing)
	}
	l.groupSlot[group] = slot
	l.mu.Unlock()
	if wait := slot.Sub(now); wait > 0 {
		if err := l.sleep(ctx, wait); err != nil {
			releaseHost()
			releaseSem()
			return nil, err
		}
	}
	if ctx.Err() != nil {
		releaseHost()
		releaseSem()
		return nil, ctx.Err()
	}

	l.mu.Lock()
	if l.HostCap > 0 {
		l.state.HostProbes[host] = append(l.state.HostProbes[host], l.now())
		l.persistLocked()
	}
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			releaseHost()
			releaseSem()
		})
	}, nil
}

// Report feeds a finished probe back: 403/CAPTCHA stop the host for the rest
// of the run; 429 blocks the host until Retry-After / reset headers or, when
// absent, for DefaultBlock, and the block is persisted.
func (l *Limiter) Report(host string, r *model.ProbeResult) { l.ReportScoped(host, "", r) }

// ReportScoped is Report with a scope for the per-run block (see AllowanceScoped).
func (l *Limiter) ReportScoped(host, scope string, r *model.ProbeResult) {
	if r == nil || r.HTTP == nil {
		return
	}
	host = strings.ToLower(host)
	key := host + "|" + scope
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case r.HTTP.Captcha:
		l.runBlocked[key] = Allowance{Code: "run_block_captcha", Reason: i18n.T("сервер потребовал проверку (CAPTCHA); пробы этого хоста остановлены до конца запуска")}
	case r.HTTP.Status == 403:
		l.runBlocked[key] = Allowance{Code: "run_block_403", Reason: i18n.T("сервер ответил 403; пробы этого хоста остановлены до конца запуска")}
	case r.HTTP.Status == 429:
		now := l.now()
		until := now.Add(l.DefaultBlock)
		reason := i18n.T("сервер ответил 429 без Retry-After; локальная пауза 15 минут")
		if r.HTTP.RateLimitReset != "" {
			if t, err := time.Parse(time.RFC3339, r.HTTP.RateLimitReset); err == nil && t.After(now) {
				until = t
				reason = i18n.T("сервер ответил 429; повтор после указанного сервером времени")
			}
		}
		l.state.HostBlocks[host] = Block{Until: until, Reason: reason, Status: 429}
		l.runBlocked[key] = Allowance{Code: "rate_limited_429", Reason: reason, Until: until}
		l.persistLocked()
	}
}

// Snapshot returns a copy of the persisted state (for diagnostics/UI).
func (l *Limiter) Snapshot() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked()
	out := State{SchemaVersion: l.state.SchemaVersion, HostProbes: map[string][]time.Time{}, HostBlocks: map[string]Block{}}
	if l.state.LastRunStart != nil {
		t := *l.state.LastRunStart
		out.LastRunStart = &t
	}
	for h, ts := range l.state.HostProbes {
		out.HostProbes[h] = append([]time.Time(nil), ts...)
	}
	for h, b := range l.state.HostBlocks {
		out.HostBlocks[h] = b
	}
	return out
}
