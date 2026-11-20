package limiter

import (
	"errors"
	"testing"
	"time"
)

func TestSpeedCooldownDailyCapAndPersist(t *testing.T) {
	dir := t.TempDir()
	l, clk := newLimiter(t, dir)
	l.SpeedCooldown = 3 * time.Minute
	l.SpeedDailyCap = 3
	if err := l.StartSpeed("a"); err != nil {
		t.Fatal(err)
	}
	if err := l.StartSpeed("a"); !errors.Is(err, ErrSpeedActive) {
		t.Fatalf("second speed test while one runs: %v", err)
	}
	if err := l.StartRun(); !errors.Is(err, ErrSpeedActive) {
		t.Fatalf("probe run during speed test: %v", err)
	}
	l.EndSpeed()
	clk.Advance(time.Minute)
	var ce *CooldownError
	if err := l.StartSpeed("a"); !errors.As(err, &ce) || ce.Wait != 2*time.Minute {
		t.Fatalf("cooldown: %v", err)
	}
	// Restart keeps the cooldown.
	l2 := New(l.st, clk.Now)
	l2.SpeedCooldown, l2.SpeedDailyCap = 3*time.Minute, 3
	if err := l2.StartSpeed("a"); !errors.As(err, &ce) {
		t.Fatalf("cooldown lost after restart: %v", err)
	}
	for i := 0; i < 2; i++ {
		clk.Advance(3 * time.Minute)
		if err := l2.StartSpeed("a"); err != nil {
			t.Fatal(err)
		}
		l2.EndSpeed()
	}
	clk.Advance(3 * time.Minute)
	var dc *DailyCapError
	if err := l2.StartSpeed("a"); !errors.As(err, &dc) || dc.Cap != 3 {
		t.Fatalf("daily cap: %v", err)
	}
	if s := l2.Speed(); s.Used24h != 3 || s.CapFreeAt == nil {
		t.Fatalf("status %+v", s)
	}
	clk.Advance(24 * time.Hour)
	if err := l2.StartSpeed("a"); err != nil {
		t.Fatalf("cap must free after 24 h: %v", err)
	}
}

func TestSpeedRefusedDuringRunAndBlockPersists(t *testing.T) {
	dir := t.TempDir()
	l, clk := newLimiter(t, dir)
	l.SpeedCooldown = 0
	if err := l.StartRun(); err != nil {
		t.Fatal(err)
	}
	if err := l.StartSpeed("a"); !errors.Is(err, ErrRunActive) {
		t.Fatalf("speed during run: %v", err)
	}
	l.EndRun()
	l.BlockSpeedServer("a", clk.Now().Add(time.Hour), "429", 429)
	l2 := New(l.st, clk.Now)
	l2.SpeedCooldown = 0
	var be *BlockedError
	if err := l2.StartSpeed("a"); !errors.As(err, &be) || be.Block.Status != 429 {
		t.Fatalf("block lost: %v", err)
	}
	if err := l2.StartSpeed("b"); err != nil {
		t.Fatalf("other server: %v", err)
	}
	l2.EndSpeed()
	clk.Advance(time.Hour + time.Second)
	if err := l2.StartSpeed("a"); err != nil {
		t.Fatalf("block must expire: %v", err)
	}
}
