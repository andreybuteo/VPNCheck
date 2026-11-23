package limiter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpncheck/internal/model"
	"vpncheck/internal/store"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newLimiter(t *testing.T, dir string) (*Limiter, *fakeClock) {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)}
	l := New(st, clk.Now)
	// Fake sleep that advances the clock instead of waiting.
	l.SetSleep(func(ctx context.Context, d time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		clk.Advance(d)
		return nil
	})
	return l, clk
}

func TestCooldownAndSingleRunPersist(t *testing.T) {
	dir := t.TempDir()
	l, clk := newLimiter(t, dir)
	if err := l.StartRun(); err != nil {
		t.Fatal(err)
	}
	if err := l.StartRun(); !errors.Is(err, ErrRunActive) {
		t.Fatalf("second start during run: want ErrRunActive, got %v", err)
	}
	l.EndRun()
	clk.Advance(20 * time.Second)
	err := l.StartRun()
	var ce *CooldownError
	if !errors.As(err, &ce) || ce.Wait != 40*time.Second {
		t.Fatalf("want cooldown 40s, got %v", err)
	}
	// Restart the process: cooldown must survive.
	l2 := New(l.st, clk.Now)
	if err := l2.StartRun(); !errors.As(err, &ce) {
		t.Fatalf("cooldown lost after restart: %v", err)
	}
	clk.Advance(40 * time.Second)
	if err := l2.StartRun(); err != nil {
		t.Fatalf("after cooldown: %v", err)
	}
}

func TestSetRunCooldownAppliesToCurrentWait(t *testing.T) {
	l, clk := newLimiter(t, t.TempDir())
	l.RunCooldown = 60 * time.Second
	if err := l.StartRun(); err != nil {
		t.Fatal(err)
	}
	l.EndRun()
	clk.Advance(20 * time.Second)
	l.SetRunCooldown(15 * time.Second)
	if got := l.Cooldown(); got != 15*time.Second {
		t.Fatalf("Cooldown() = %v", got)
	}
	if !l.CooldownUntil().IsZero() {
		t.Fatal("shorter pause must end the current wait")
	}
	if err := l.StartRun(); err != nil {
		t.Fatalf("start after shorter pause: %v", err)
	}
	l.EndRun()
	l.SetRunCooldown(5 * time.Minute)
	clk.Advance(time.Minute)
	var ce *CooldownError
	if err := l.StartRun(); !errors.As(err, &ce) || ce.Wait != 4*time.Minute {
		t.Fatalf("want wait 4m with longer pause, got %v", err)
	}
}

func TestHourlyCapSlidingWindowPersists(t *testing.T) {
	dir := t.TempDir()
	l, clk := newLimiter(t, dir)
	l.HostCap = 12
	_ = l.StartRun()
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		rel, err := l.Acquire(ctx, "API.Example.com", "g")
		if err != nil {
			t.Fatal(err)
		}
		rel()
		clk.Advance(time.Minute)
	}
	a := l.Allowance("api.example.com")
	if a.OK || a.Code != "hourly_cap" {
		t.Fatalf("13th probe within an hour must be refused: %+v", a)
	}
	wantUntil := time.Date(2026, 9, 13, 13, 0, 0, 0, time.UTC) // first probe + 1h
	if !a.Until.Equal(wantUntil) {
		t.Fatalf("until=%v want %v", a.Until, wantUntil)
	}
	// Other hosts are unaffected.
	if b := l.Allowance("other.example.com"); !b.OK {
		t.Fatalf("other host should be allowed: %+v", b)
	}
	// Survives restart (and a profile change is irrelevant: state is global).
	l2 := New(l.st, clk.Now)
	l2.HostCap = 12
	// Re-load the persisted timestamps after explicitly enabling the optional cap.
	_, _ = l.st.LoadJSON(fileName, &l2.state)
	if a := l2.Allowance("api.example.com"); a.OK {
		t.Fatal("cap must persist across restart")
	}
	// The window slides: at 13:00 one probe expired, one slot frees up.
	clk.Advance(48 * time.Minute) // now 13:00
	if a := l2.Allowance("api.example.com"); !a.OK {
		t.Fatalf("window should have slid: %+v", a)
	}
}

func TestNoHourlyCapIgnoresLegacyState(t *testing.T) {
	l, clk := newLimiter(t, t.TempDir())
	stamps := make([]time.Time, 20)
	for i := range stamps {
		stamps[i] = clk.Now()
	}
	l.state.HostProbes["api.example.com"] = stamps
	l.persistLocked()
	l = New(l.st, clk.Now)
	l.GroupSpacing = 0
	for i := 0; i < 30; i++ {
		if a := l.Allowance("api.example.com"); !a.OK {
			t.Fatalf("probe %d blocked by disabled cap: %+v", i, a)
		}
		release, err := l.Acquire(context.Background(), "api.example.com", "g")
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	if len(l.Snapshot().HostProbes) != 0 {
		t.Fatal("disabled cap must not accumulate probe history")
	}
}

func TestConcurrencyLimits(t *testing.T) {
	l, _ := newLimiter(t, t.TempDir())
	l.MaxConcurrent = 4
	l.Resize()
	l.GroupSpacing = 0
	// Real sleeping for this test (polling waits).
	l.SetSleep(func(ctx context.Context, d time.Duration) error {
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	_ = l.StartRun()
	var inFlight, maxInFlight atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rel, err := l.Acquire(context.Background(), "host"+string(rune('a'+i))+".example.com", "g")
			if err != nil {
				t.Error(err)
				return
			}
			n := inFlight.Add(1)
			for {
				m := maxInFlight.Load()
				if n <= m || maxInFlight.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
			rel()
		}(i)
	}
	wg.Wait()
	if maxInFlight.Load() > 4 {
		t.Fatalf("global concurrency exceeded: %d", maxInFlight.Load())
	}

	// One in-flight probe per host.
	var same atomic.Int32
	var maxSame atomic.Int32
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := l.Acquire(context.Background(), "same.example.com", "g2")
			if err != nil {
				t.Error(err)
				return
			}
			n := same.Add(1)
			if n > maxSame.Load() {
				maxSame.Store(n)
			}
			time.Sleep(15 * time.Millisecond)
			same.Add(-1)
			rel()
		}()
	}
	wg.Wait()
	if maxSame.Load() != 1 {
		t.Fatalf("per-host concurrency exceeded: %d", maxSame.Load())
	}
}

func TestGroupStartSpacing(t *testing.T) {
	l, clk := newLimiter(t, t.TempDir())
	_ = l.StartRun()
	starts := []time.Time{}
	for _, h := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		rel, err := l.Acquire(context.Background(), h, "grp")
		if err != nil {
			t.Fatal(err)
		}
		starts = append(starts, clk.Now())
		rel()
	}
	for i := 1; i < len(starts); i++ {
		if d := starts[i].Sub(starts[i-1]); d < time.Second {
			t.Fatalf("starts inside a group must be >= 1s apart, got %v", d)
		}
	}
	// A different group is not delayed.
	before := clk.Now()
	rel, _ := l.Acquire(context.Background(), "d.example.com", "other")
	rel()
	if clk.Now().Sub(before) != 0 {
		t.Fatal("other group should start immediately")
	}
}

func TestRunBlocksAndRateLimitBlocks(t *testing.T) {
	dir := t.TempDir()
	l, clk := newLimiter(t, dir)
	_ = l.StartRun()

	l.Report("a.example.com", &model.ProbeResult{HTTP: &model.HTTPResult{Status: 403}})
	if a := l.Allowance("a.example.com"); a.OK || a.Code != "run_block_403" {
		t.Fatalf("403 must block for the run: %+v", a)
	}
	l.Report("c.example.com", &model.ProbeResult{HTTP: &model.HTTPResult{Status: 200, Captcha: true}})
	if a := l.Allowance("c.example.com"); a.OK || a.Code != "run_block_captcha" {
		t.Fatalf("captcha must block for the run: %+v", a)
	}

	// 429 with Retry-After → until that time.
	reset := clk.Now().Add(2 * time.Minute)
	l.Report("b.example.com", &model.ProbeResult{HTTP: &model.HTTPResult{Status: 429, RateLimitReset: reset.Format(time.RFC3339)}})
	if a := l.Allowance("b.example.com"); a.OK || a.Code != "rate_limited_429" || !a.Until.Equal(reset) {
		t.Fatalf("429 with reset: %+v", a)
	}
	// 429 without headers → 15 minutes.
	l.Report("d.example.com", &model.ProbeResult{HTTP: &model.HTTPResult{Status: 429}})
	if a := l.Allowance("d.example.com"); a.OK || !a.Until.Equal(clk.Now().Add(15*time.Minute)) {
		t.Fatalf("429 default block: %+v", a)
	}

	l.EndRun()
	if a := l.Allowance("a.example.com"); !a.OK {
		t.Fatal("403 block must end with the run")
	}
	if a := l.Allowance("b.example.com"); a.OK {
		t.Fatal("429 block must outlive the run")
	}
	// Survives restart (profile switch does not reset it).
	l2 := New(l.st, clk.Now)
	if a := l2.Allowance("d.example.com"); a.OK {
		t.Fatal("429 block must survive restart")
	}
	clk.Advance(16 * time.Minute)
	if a := l2.Allowance("d.example.com"); !a.OK {
		t.Fatalf("429 block must expire: %+v", a)
	}
}

func TestAcquireCancelWhileWaiting(t *testing.T) {
	l, _ := newLimiter(t, t.TempDir())
	l.HostCap = 12
	l.MaxConcurrent = 1
	l.Resize()
	l.SetSleep(func(ctx context.Context, d time.Duration) error {
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	_ = l.StartRun()
	rel, err := l.Acquire(context.Background(), "x.example.com", "g")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, "y.example.com", "g"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded while waiting for the semaphore, got %v", err)
	}
	rel()
	// Slot is usable again and the cancelled waiter left nothing behind.
	rel2, err := l.Acquire(context.Background(), "y.example.com", "g")
	if err != nil {
		t.Fatal(err)
	}
	rel2()
	if snap := l.Snapshot(); len(snap.HostProbes["y.example.com"]) != 1 {
		t.Fatalf("cancelled acquire must not count as a probe: %+v", snap.HostProbes)
	}
}

func TestCorruptStateStartsClean(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	_ = st.SaveJSON(fileName, map[string]any{"hostProbes": "not a map"})
	l := New(st, time.Now)
	if err := l.StartRun(); err != nil {
		t.Fatalf("corrupt limiter state must not block: %v", err)
	}
}

func TestQueuedProbeHonoursRefusal(t *testing.T) {
	l, _ := newLimiter(t, t.TempDir())
	held, err := l.Acquire(context.Background(), "a.example", "g")
	if err != nil {
		t.Fatal(err)
	}
	waiting, resume := make(chan struct{}), make(chan struct{})
	l.SetSleep(func(_ context.Context, _ time.Duration) error {
		close(waiting)
		<-resume
		return nil
	})
	result := make(chan error, 1)
	go func() {
		release, err := l.Acquire(context.Background(), "a.example", "g2")
		if release != nil {
			release()
		}
		result <- err
	}()
	<-waiting
	l.Report("a.example", &model.ProbeResult{HTTP: &model.HTTPResult{Status: 429, Captcha: true}})
	held()
	close(resume)
	var denied *Allowance
	if err := <-result; !errors.As(err, &denied) || denied.Code != "rate_limited_429" {
		t.Fatalf("queued request: %v", err)
	}
	l.EndRun()
	if l.Allowance("a.example").OK {
		t.Fatal("429 with challenge must persist")
	}
}

func TestFailedQuotaWriteDoesNotClaimSlot(t *testing.T) {
	dir := t.TempDir()
	l, _ := newLimiter(t, dir)
	path := filepath.Join(dir, fileName)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if l.StartRun() == nil || l.StartSpeed("s.example") == nil || l.SaveError() == nil {
		t.Fatal("unrecorded reservation accepted")
	}
	if l.RunActive() || l.Speed().Active || l.Speed().Used24h != 0 {
		t.Fatal("failed reservation consumed quota")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := l.StartSpeed("s.example"); err != nil || l.SaveError() != nil {
		t.Fatal("could not recover after write failure")
	}
	l.EndSpeed()
}
