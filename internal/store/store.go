// Package store persists settings, run history and limiter state as JSON
// files under the data directory. Every write is atomic (temp file + rename);
// a corrupt file is moved aside and reported instead of being overwritten,
// and one damaged run never hides the rest of the history.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

const (
	settingsFile = "settings.json"
	indexFile    = "index.json"
	historyDir   = "history"
)

var runIDRe = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)

// ErrInvalidID is returned for run IDs that could escape the history directory.
var ErrInvalidID = errors.New("недопустимый идентификатор запуска")

// LoadInfo reports how a load went.
type LoadInfo struct {
	Found   bool   // the file existed
	Corrupt bool   // the file existed but could not be parsed; it was moved to BackupPath
	Backup  string // path of the moved-aside corrupt file
}

// Store is the on-disk JSON store.
type Store struct {
	dir          string
	mu           sync.Mutex
	HistoryLimit int
}

// Open prepares the store in dir (created if missing).
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, historyDir), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, HistoryLimit: app.HistoryLimit}, nil
}

// Dir returns the data directory.
func (s *Store) Dir() string { return s.dir }

// SaveJSON atomically writes v as indented JSON to name (relative to the data dir).
func (s *Store) SaveJSON(name string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWrite(filepath.Join(s.dir, name), v)
}

// LoadJSON reads name into v. A missing file yields Found=false and v untouched.
// A corrupt file is moved aside and reported via Corrupt=true; v is untouched.
func (s *Store) LoadJSON(name string, v any) (LoadInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return loadJSON(filepath.Join(s.dir, name), v)
}

// LoadSettings returns the settings or defaults when missing/corrupt.
func (s *Store) LoadSettings() (model.Settings, LoadInfo, error) {
	st := model.DefaultSettings()
	info, err := s.LoadJSON(settingsFile, &st)
	if err != nil || info.Corrupt || !info.Found {
		st = model.DefaultSettings()
	}
	if st.SchemaVersion == 0 {
		st.SchemaVersion = model.SchemaVersion
	}
	if st.SlowThresholdMs <= 0 {
		st.SlowThresholdMs = model.DefaultSettings().SlowThresholdMs
	}
	if st.SpeedServer == "" {
		st.SpeedServer = model.DefaultSettings().SpeedServer
	}
	if st.RunCooldownSec <= 0 {
		st.RunCooldownSec = model.DefaultSettings().RunCooldownSec
	}
	if st.Route.Mode == "" {
		st.Route.Mode = model.RouteSystem
	}
	if st.IPFamily == "" {
		st.IPFamily = model.FamilyAuto
	}
	if st.Mode == "" {
		st.Mode = model.ModeFast
	}
	if st.Theme != "light" {
		st.Theme = "dark"
	}
	return st, info, err
}

// SaveSettings persists the settings.
func (s *Store) SaveSettings(st model.Settings) error {
	st.SchemaVersion = model.SchemaVersion
	return s.SaveJSON(settingsFile, st)
}

// NewRunID returns a sortable unique run identifier.
func NewRunID(t time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return t.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

func (s *Store) runPath(id string) (string, error) {
	if !runIDRe.MatchString(id) {
		return "", ErrInvalidID
	}
	return filepath.Join(s.dir, historyDir, id+".json"), nil
}

// SaveRun writes the run file, updates the index and prunes old runs.
func (s *Store) SaveRun(run *model.Run) error {
	path, err := s.runPath(run.ID)
	if err != nil {
		return err
	}
	snapshot := *run
	snapshot.SchemaVersion = model.SchemaVersion
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := atomicWrite(path, &snapshot); err != nil {
		return err
	}
	idx := s.readIndexLocked()
	replaced := false
	sum := run.Summary()
	for i := range idx {
		if idx[i].ID == run.ID {
			idx[i] = sum
			replaced = true
			break
		}
	}
	if !replaced {
		idx = append(idx, sum)
	}
	sortSummaries(idx)
	if len(idx) > s.HistoryLimit {
		for _, old := range idx[s.HistoryLimit:] {
			if p, err := s.runPath(old.ID); err == nil {
				_ = os.Remove(p)
			}
		}
		idx = idx[:s.HistoryLimit]
	}
	return atomicWrite(filepath.Join(s.dir, historyDir, indexFile), idx)
}

// ListRuns returns the history, newest first. The index is rebuilt from the
// run files when it is missing or corrupt.
func (s *Store) ListRuns() ([]model.RunSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.readIndexLocked()
	return idx, nil
}

// LoadRun reads a complete run.
func (s *Store) LoadRun(id string) (*model.Run, error) {
	path, err := s.runPath(id)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var run model.Run
	info, err := loadJSON(path, &run)
	if err != nil {
		return nil, err
	}
	if !info.Found {
		return nil, os.ErrNotExist
	}
	if info.Corrupt {
		return nil, i18n.Errorf("файл запуска повреждён и перемещён в %s", filepath.Base(info.Backup))
	}
	return &run, nil
}

// DeleteRun removes a run and its index entry.
func (s *Store) DeleteRun(id string) error {
	path, err := s.runPath(id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	idx := s.readIndexLocked()
	out := idx[:0]
	for _, e := range idx {
		if e.ID != id {
			out = append(out, e)
		}
	}
	return atomicWrite(filepath.Join(s.dir, historyDir, indexFile), out)
}

func (s *Store) readIndexLocked() []model.RunSummary {
	var idx []model.RunSummary
	info, err := loadJSON(filepath.Join(s.dir, historyDir, indexFile), &idx)
	if err == nil && info.Found && !info.Corrupt && idx != nil {
		sortSummaries(idx)
		return idx
	}
	return s.rebuildIndexLocked()
}

func (s *Store) rebuildIndexLocked() []model.RunSummary {
	entries, err := os.ReadDir(filepath.Join(s.dir, historyDir))
	if err != nil {
		return []model.RunSummary{}
	}
	idx := []model.RunSummary{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == indexFile || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !runIDRe.MatchString(id) {
			continue
		}
		var run model.Run
		info, err := loadJSON(filepath.Join(s.dir, historyDir, name), &run)
		if err != nil || !info.Found || info.Corrupt || run.ID != id {
			continue
		}
		idx = append(idx, run.Summary())
	}
	sortSummaries(idx)
	_ = atomicWrite(filepath.Join(s.dir, historyDir, indexFile), idx)
	return idx
}

func sortSummaries(idx []model.RunSummary) {
	sort.SliceStable(idx, func(i, j int) bool {
		if !idx[i].StartedAt.Equal(idx[j].StartedAt) {
			return idx[i].StartedAt.After(idx[j].StartedAt)
		}
		return idx[i].ID > idx[j].ID
	})
}

// atomicWrite marshals v and replaces path atomically.
func atomicWrite(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// loadJSON reads path into v; see LoadInfo for semantics.
func loadJSON(path string, v any) (LoadInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LoadInfo{}, nil
		}
		return LoadInfo{}, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		backup := fmt.Sprintf("%s.corrupt-%s", path, time.Now().UTC().Format("20060102-150405"))
		if renameErr := os.Rename(path, backup); renameErr != nil {
			backup = ""
		}
		return LoadInfo{Found: true, Corrupt: true, Backup: backup}, nil
	}
	return LoadInfo{Found: true}, nil
}
