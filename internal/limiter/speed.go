package limiter

import (
	"errors"
	"time"

	"vpncheck/internal/i18n"
)

// ErrSpeedActive is returned when a speed test is in progress.
var ErrSpeedActive = errors.New("идёт замер скорости")

// DailyCapError reports that the 24-hour speed-test cap is used up.
type DailyCapError struct {
	Cap   int
	Until time.Time
}

func (e *DailyCapError) Error() string {
	return i18n.T("исчерпан суточный лимит замеров скорости")
}

// BlockedError reports a speed server paused after 429/403/challenge.
type BlockedError struct {
	Host  string
	Block Block
}

func (e *BlockedError) Error() string {
	return i18n.T("сервер замера ") + e.Host + i18n.T(" временно не используется: ") + e.Block.Reason
}

// SpeedStatus is the public view of the speed-test limits.
type SpeedStatus struct {
	Active        bool             `json:"active"`
	CooldownUntil *time.Time       `json:"cooldownUntil"`
	Used24h       int              `json:"used24h"`
	DailyCap      int              `json:"dailyCap"`
	CapFreeAt     *time.Time       `json:"capFreeAt"`
	CooldownSec   int              `json:"cooldownSec"`
	Blocks        map[string]Block `json:"blocks"`
}

// StartSpeed claims the speed-test slot. A speed test never overlaps a probe
// run, keeps SpeedCooldown between starts and at most SpeedDailyCap starts in
// any 24 hours, and is refused for a server paused after 429/403/challenge.
// The claim is persisted at once, so a restart does not reset the limits.
func (l *Limiter) StartSpeed(host string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runActive {
		return ErrRunActive
	}
	if l.speedActive {
		return ErrSpeedActive
	}
	l.pruneLocked()
	now := l.now()
	if b, ok := l.state.SpeedBlocks[host]; ok && b.Until.After(now) {
		return &BlockedError{Host: host, Block: b}
	}
	if l.state.LastSpeedStart != nil {
		if until := l.state.LastSpeedStart.Add(l.SpeedCooldown); until.After(now) {
			return &CooldownError{Wait: until.Sub(now), Until: until}
		}
	}
	if l.SpeedDailyCap > 0 && len(l.state.SpeedStarts) >= l.SpeedDailyCap {
		return &DailyCapError{Cap: l.SpeedDailyCap, Until: l.state.SpeedStarts[0].Add(24 * time.Hour)}
	}
	t := now
	l.state.LastSpeedStart = &t
	l.state.SpeedStarts = append(l.state.SpeedStarts, t)
	l.speedActive = true
	l.persistLocked()
	return nil
}

// EndSpeed releases the speed-test slot.
func (l *Limiter) EndSpeed() {
	l.mu.Lock()
	l.speedActive = false
	l.mu.Unlock()
}

// BlockSpeedServer pauses a speed server until the given time (persisted).
func (l *Limiter) BlockSpeedServer(host string, until time.Time, reason string, status int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state.SpeedBlocks == nil {
		l.state.SpeedBlocks = map[string]Block{}
	}
	l.state.SpeedBlocks[host] = Block{Until: until, Reason: reason, Status: status}
	l.persistLocked()
}

// Speed returns the current speed-test limits.
func (l *Limiter) Speed() SpeedStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked()
	now := l.now()
	v := SpeedStatus{Active: l.speedActive, Used24h: len(l.state.SpeedStarts), DailyCap: l.SpeedDailyCap,
		CooldownSec: int(l.SpeedCooldown.Seconds()), Blocks: map[string]Block{}}
	if l.state.LastSpeedStart != nil {
		if until := l.state.LastSpeedStart.Add(l.SpeedCooldown); until.After(now) {
			u := until.UTC()
			v.CooldownUntil = &u
		}
	}
	if l.SpeedDailyCap > 0 && len(l.state.SpeedStarts) >= l.SpeedDailyCap {
		u := l.state.SpeedStarts[0].Add(24 * time.Hour).UTC()
		v.CapFreeAt = &u
	}
	for h, b := range l.state.SpeedBlocks {
		v.Blocks[h] = b
	}
	return v
}
