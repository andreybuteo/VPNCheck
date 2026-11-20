package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpncheck/internal/model"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mkRun(id string, at time.Time) *model.Run {
	return &model.Run{
		ID:          id,
		ProfileName: "VPN — Тест",
		StartedAt:   at,
		Mode:        model.ModeFast,
		Route:       model.RouteConfig{Mode: model.RouteSystem},
		IPFamily:    model.FamilyAuto,
		Status:      model.RunCompleted,
		Endpoints:   []model.Endpoint{},
		Results:     []model.ProbeResult{},
	}
}

func TestSettingsRoundTripAndDefaults(t *testing.T) {
	s := newStore(t)
	st, info, err := s.LoadSettings()
	if err != nil || info.Found {
		t.Fatalf("fresh store: err=%v info=%+v", err, info)
	}
	if st.Theme != "dark" || st.Route.Mode != model.RouteSystem || st.SlowThresholdMs <= 0 {
		t.Fatalf("defaults wrong: %+v", st)
	}
	st.ProfileName = "VPN — Германия"
	st.Route = model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "127.0.0.1:10809"}
	if err := s.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	got, info, err := s.LoadSettings()
	if err != nil || !info.Found || info.Corrupt {
		t.Fatalf("load: err=%v info=%+v", err, info)
	}
	if got.ProfileName != st.ProfileName || got.Route != st.Route {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	entries, _ := os.ReadDir(s.Dir())
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestCorruptSettingsAreMovedAsideNotDeleted(t *testing.T) {
	s := newStore(t)
	path := filepath.Join(s.Dir(), settingsFile)
	if err := os.WriteFile(path, []byte(`{"profileName": "broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, info, err := s.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !info.Corrupt || info.Backup == "" {
		t.Fatalf("corrupt not reported: %+v", info)
	}
	if _, err := os.Stat(info.Backup); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt file should have been moved")
	}
	if st.Theme != "dark" {
		t.Fatalf("defaults expected after corruption, got %+v", st)
	}
	// Second load: clean state, no error.
	_, info, _ = s.LoadSettings()
	if info.Found || info.Corrupt {
		t.Fatalf("expected empty state, got %+v", info)
	}
}

func TestHistorySaveListLoadPrune(t *testing.T) {
	s := newStore(t)
	s.HistoryLimit = 3
	base := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		if err := s.SaveRun(mkRun(NewRunID(at), at)); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListRuns()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("want 3 runs after prune, got %d", len(list))
	}
	if !list[0].StartedAt.After(list[1].StartedAt) {
		t.Fatal("history must be newest first")
	}
	if list[2].StartedAt != base.Add(2*time.Minute) {
		t.Fatalf("oldest kept run wrong: %v", list[2].StartedAt)
	}
	files, _ := os.ReadDir(filepath.Join(s.Dir(), historyDir))
	runFiles := 0
	for _, f := range files {
		if f.Name() != indexFile {
			runFiles++
		}
	}
	if runFiles != 3 {
		t.Fatalf("want 3 run files on disk, got %d", runFiles)
	}
	run, err := s.LoadRun(list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.ProfileName != "VPN — Тест" || run.SchemaVersion != model.SchemaVersion {
		t.Fatalf("loaded run wrong: %+v", run)
	}
}

func TestCorruptRunDoesNotHideOthers(t *testing.T) {
	s := newStore(t)
	at := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	good := mkRun(NewRunID(at), at)
	if err := s.SaveRun(good); err != nil {
		t.Fatal(err)
	}
	badID := NewRunID(at.Add(time.Minute))
	badPath := filepath.Join(s.Dir(), historyDir, badID+".json")
	if err := os.WriteFile(badPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Drop the index to force a rebuild from files.
	os.Remove(filepath.Join(s.Dir(), historyDir, indexFile))
	list, err := s.ListRuns()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != good.ID {
		t.Fatalf("rebuild should list only the good run, got %+v", list)
	}
	if _, err := s.LoadRun(badID); err == nil {
		t.Fatal("loading corrupt run must fail")
	}
}

func TestCorruptIndexIsRebuilt(t *testing.T) {
	s := newStore(t)
	at := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	r := mkRun(NewRunID(at), at)
	if err := s.SaveRun(r); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir(), historyDir, indexFile), []byte("[[["), 0o600); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListRuns()
	if len(list) != 1 || list[0].ID != r.ID {
		t.Fatalf("index rebuild failed: %+v", list)
	}
}

func TestInvalidRunIDRejected(t *testing.T) {
	s := newStore(t)
	for _, id := range []string{"../settings", "a/b", "", "x\\y", strings.Repeat("a", 65)} {
		if _, err := s.LoadRun(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("id %q: want ErrInvalidID, got %v", id, err)
		}
		if err := s.SaveRun(mkRun(id, time.Now())); !errors.Is(err, ErrInvalidID) {
			t.Errorf("save id %q: want ErrInvalidID, got %v", id, err)
		}
	}
}

func TestDeleteRun(t *testing.T) {
	s := newStore(t)
	at := time.Now().UTC()
	r := mkRun(NewRunID(at), at)
	_ = s.SaveRun(r)
	if err := s.DeleteRun(r.ID); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListRuns()
	if len(list) != 0 {
		t.Fatalf("want empty history, got %d", len(list))
	}
}

func TestConcurrentSavesAreSafe(t *testing.T) {
	s := newStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			at := time.Date(2026, 9, 13, 10, i, 0, 0, time.UTC)
			if err := s.SaveRun(mkRun(NewRunID(at), at)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	list, _ := s.ListRuns()
	if len(list) != 20 {
		t.Fatalf("want 20, got %d", len(list))
	}
}

func TestMsRounding(t *testing.T) {
	v := model.Ms(1234567 * time.Nanosecond)
	if *v != 1.2 {
		t.Fatalf("want 1.2, got %v", *v)
	}
}
