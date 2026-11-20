// Package registry holds the set of control points. The built-in profile is
// embedded from default.json; the user may enable/disable points, add custom
// public HTTPS hosts, and import/export the whole list as JSON. Imports are
// validated completely before they replace anything.
package registry

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"vpncheck/internal/guard"
	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
	"vpncheck/internal/probe"
	"vpncheck/internal/store"
)

// ProfileVersion is bumped whenever default.json changes materially.
const ProfileVersion = 1

const fileName = "registry.json"

//go:embed default.json
var defaultJSON []byte

// Document is the on-disk / import / export format.
type Document struct {
	SchemaVersion  int              `json:"schemaVersion"`
	ProfileVersion int              `json:"profileVersion"`
	Endpoints      []model.Endpoint `json:"endpoints"`
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Defaults returns a copy of the built-in endpoints.
func Defaults() []model.Endpoint {
	var doc Document
	if err := json.Unmarshal(defaultJSON, &doc); err != nil {
		panic("registry: embedded default.json is invalid: " + err.Error())
	}
	return doc.Endpoints
}

// Registry is the live, persisted endpoint list.
type Registry struct {
	mu     sync.RWMutex
	eps    []model.Endpoint
	st     *store.Store
	policy guard.Policy
	// builtin holds the IDs of the embedded profile: they cannot be deleted or
	// re-targeted, only enabled/disabled.
	builtin map[string]model.Endpoint
}

// LoadInfo reports how the registry file was loaded.
type LoadInfo struct {
	store.LoadInfo
	// Invalid is set when the file parsed but failed validation; defaults were used
	// and the file was left in place.
	Invalid string
}

// Load reads registry.json or falls back to the embedded defaults.
func Load(st *store.Store) (*Registry, LoadInfo) {
	r := &Registry{st: st, policy: guard.Default(), builtin: map[string]model.Endpoint{}}
	for _, e := range Defaults() {
		r.builtin[e.ID] = e
	}
	var info LoadInfo
	var doc Document
	li, err := st.LoadJSON(fileName, &doc)
	info.LoadInfo = li
	if err == nil && li.Found && !li.Corrupt {
		if verr := r.validateAll(doc.Endpoints); verr == nil {
			r.eps = doc.Endpoints
			r.mergeNewDefaults()
			return r, info
		} else {
			info.Invalid = verr.Error()
		}
	}
	r.eps = Defaults()
	return r, info
}

// mergeNewDefaults appends built-in endpoints that a newer version added and
// the user's file does not know about yet (they keep their default state).
func (r *Registry) mergeNewDefaults() {
	have := map[string]bool{}
	for _, e := range r.eps {
		have[e.ID] = true
	}
	for _, d := range Defaults() {
		if !have[d.ID] {
			r.eps = append(r.eps, d)
		}
	}
}

// List returns a copy of all endpoints in profile order.
func (r *Registry) List() []model.Endpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.Endpoint, len(r.eps))
	copy(out, r.eps)
	return out
}

// Enabled returns the enabled endpoints.
func (r *Registry) Enabled() []model.Endpoint {
	var out []model.Endpoint
	for _, e := range r.List() {
		if e.Enabled {
			out = append(out, e)
		}
	}
	return out
}

// Get returns one endpoint.
func (r *Registry) Get(id string) (model.Endpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.eps {
		if e.ID == id {
			return e, true
		}
	}
	return model.Endpoint{}, false
}

// IsBuiltin reports whether id belongs to the embedded profile.
func (r *Registry) IsBuiltin(id string) bool {
	_, ok := r.builtin[id]
	return ok
}

// Groups returns group IDs and names in order of first appearance.
func (r *Registry) Groups() []struct{ ID, Name string } {
	seen := map[string]bool{}
	var out []struct{ ID, Name string }
	for _, e := range r.List() {
		if !seen[e.GroupID] {
			seen[e.GroupID] = true
			out = append(out, struct{ ID, Name string }{e.GroupID, e.Group})
		}
	}
	return out
}

// SetEnabled toggles an endpoint.
func (r *Registry) SetEnabled(id string, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.eps {
		if r.eps[i].ID == id {
			r.eps[i].Enabled = enabled
			return r.saveLocked()
		}
	}
	return errors.New(i18n.T("контрольная точка не найдена"))
}

// Upsert adds or updates a custom endpoint. Built-in endpoints cannot be edited
// this way (only enabled/disabled).
func (r *Registry) Upsert(ep model.Endpoint) error {
	ep = normalize(ep)
	ep.Custom = true
	ep.Source = strings.TrimSpace(ep.Source)
	if ep.VerifiedAt == "" {
		ep.VerifiedAt = time.Now().UTC().Format("2006-01-02")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, isBuiltin := r.builtin[ep.ID]; isBuiltin {
		return errors.New(i18n.T("встроенную точку нельзя изменять; её можно только включить или выключить"))
	}
	next := make([]model.Endpoint, 0, len(r.eps)+1)
	replaced := false
	for _, e := range r.eps {
		if e.ID == ep.ID {
			next = append(next, ep)
			replaced = true
		} else {
			next = append(next, e)
		}
	}
	if !replaced {
		next = append(next, ep)
	}
	if err := r.validateAll(next); err != nil {
		return err
	}
	r.eps = next
	return r.saveLocked()
}

// Delete removes a custom endpoint.
func (r *Registry) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, isBuiltin := r.builtin[id]; isBuiltin {
		return errors.New(i18n.T("встроенную точку нельзя удалить; её можно выключить"))
	}
	next := r.eps[:0:0]
	found := false
	for _, e := range r.eps {
		if e.ID == id {
			found = true
			continue
		}
		next = append(next, e)
	}
	if !found {
		return errors.New(i18n.T("контрольная точка не найдена"))
	}
	r.eps = next
	return r.saveLocked()
}

// Reset restores the embedded profile.
func (r *Registry) Reset() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eps = Defaults()
	return r.saveLocked()
}

// Import validates a complete document and replaces the list only if every
// endpoint is valid. On error nothing changes.
func (r *Registry) Import(data []byte) error {
	if len(data) > 1<<20 {
		return errors.New(i18n.T("файл слишком большой (лимит 1 МиБ)"))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return i18n.Errorf("некорректный JSON: %s", shortErr(err))
	}
	if doc.SchemaVersion != model.SchemaVersion {
		return i18n.Errorf("неподдерживаемая версия схемы %d (ожидается %d)", doc.SchemaVersion, model.SchemaVersion)
	}
	if len(doc.Endpoints) == 0 {
		return errors.New(i18n.T("список контрольных точек пуст"))
	}
	if len(doc.Endpoints) > 200 {
		return errors.New(i18n.T("слишком много контрольных точек (лимит 200)"))
	}
	eps := make([]model.Endpoint, 0, len(doc.Endpoints))
	for _, e := range doc.Endpoints {
		e = normalize(e)
		if b, isBuiltin := r.builtin[e.ID]; isBuiltin {
			// Built-in identity is fixed: only the enabled flag is taken from the import.
			b.Enabled = e.Enabled
			e = b
		} else {
			e.Custom = true
		}
		eps = append(eps, e)
	}
	if err := r.validateAll(eps); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eps = eps
	r.mergeNewDefaults()
	return r.saveLocked()
}

// Export serialises the current list.
func (r *Registry) Export() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return json.MarshalIndent(r.docLocked(), "", "  ")
}

func (r *Registry) docLocked() Document {
	eps := make([]model.Endpoint, len(r.eps))
	copy(eps, r.eps)
	return Document{SchemaVersion: model.SchemaVersion, ProfileVersion: ProfileVersion, Endpoints: eps}
}

func (r *Registry) saveLocked() error {
	if r.st == nil {
		return nil
	}
	return r.st.SaveJSON(fileName, r.docLocked())
}

func normalize(e model.Endpoint) model.Endpoint {
	e.ID = strings.ToLower(strings.TrimSpace(e.ID))
	e.GroupID = strings.ToLower(strings.TrimSpace(e.GroupID))
	e.Group = strings.TrimSpace(e.Group)
	e.Label = strings.TrimSpace(e.Label)
	e.Host = strings.ToLower(strings.TrimSpace(e.Host))
	e.URL = strings.TrimSpace(e.URL)
	e.Kind = model.ProbeKind(strings.ToLower(strings.TrimSpace(string(e.Kind))))
	return e
}

// Validate checks a single endpoint against the rules for public HTTPS
// control points. It is exported so the API can validate before applying.
func Validate(e model.Endpoint, policy guard.Policy) error {
	e = normalize(e)
	if !idRe.MatchString(e.ID) {
		return i18n.Errorf("точка %q: id должен состоять из латинских букв, цифр и дефиса (1–64 символа)", e.ID)
	}
	if !idRe.MatchString(e.GroupID) {
		return i18n.Errorf("точка %q: некорректный идентификатор группы", e.ID)
	}
	if e.Group == "" || len(e.Group) > 60 {
		return i18n.Errorf("точка %q: название группы обязательно (до 60 символов)", e.ID)
	}
	if len(e.Label) > 80 {
		return i18n.Errorf("точка %q: подпись слишком длинная", e.ID)
	}
	if err := policy.ValidateHostname(e.Host); err != nil {
		return i18n.Errorf("точка %q: хост: %v", e.ID, err)
	}
	if strings.Contains(e.Host, "*") {
		return i18n.Errorf("точка %q: wildcard-имена не допускаются", e.ID)
	}
	switch e.Kind {
	case model.KindTLS:
		if e.URL != "" {
			return i18n.Errorf("точка %q: для типа tls URL не задаётся", e.ID)
		}
		if len(e.Headers) > 0 {
			return i18n.Errorf("точка %q: для типа tls заголовки не задаются", e.ID)
		}
	case model.KindHTTPS:
		if e.URL == "" {
			return i18n.Errorf("точка %q: для типа https нужен URL", e.ID)
		}
		if len(e.URL) > 2048 {
			return i18n.Errorf("точка %q: URL слишком длинный", e.ID)
		}
		u, err := url.Parse(e.URL)
		if err != nil {
			return i18n.Errorf("точка %q: некорректный URL", e.ID)
		}
		if u.Scheme != "https" {
			return i18n.Errorf("точка %q: допускается только схема https", e.ID)
		}
		if u.User != nil {
			return i18n.Errorf("точка %q: URL не должен содержать логин или пароль", e.ID)
		}
		if p := u.Port(); p != "" && p != "443" {
			return i18n.Errorf("точка %q: допускается только порт 443", e.ID)
		}
		if !strings.EqualFold(u.Hostname(), e.Host) {
			return i18n.Errorf("точка %q: хост в URL (%s) не совпадает с полем host (%s)", e.ID, u.Hostname(), e.Host)
		}
		if u.Fragment != "" {
			return i18n.Errorf("точка %q: URL не должен содержать фрагмент", e.ID)
		}
		if len(e.Headers) > 4 {
			return i18n.Errorf("точка %q: слишком много заголовков", e.ID)
		}
		for k, v := range e.Headers {
			ok := false
			for _, a := range probe.AllowedRequestHeaders {
				if strings.EqualFold(a, k) {
					ok = true
				}
			}
			if !ok {
				return i18n.Errorf("точка %q: заголовок %q не разрешён (допустимы: %s)", e.ID, k, strings.Join(probe.AllowedRequestHeaders, ", "))
			}
			if len(v) == 0 || len(v) > 200 || strings.ContainsAny(v, "\r\n\x00") {
				return i18n.Errorf("точка %q: некорректное значение заголовка %q", e.ID, k)
			}
		}
	default:
		return i18n.Errorf("точка %q: тип должен быть tls или https", e.ID)
	}
	if len(e.ExpectedStatuses) > 10 {
		return i18n.Errorf("точка %q: слишком много ожидаемых статусов", e.ID)
	}
	for _, s := range e.ExpectedStatuses {
		if s < 100 || s > 599 {
			return i18n.Errorf("точка %q: недопустимый HTTP-статус %d", e.ID, s)
		}
	}
	if e.Source != "" {
		if len(e.Source) > 500 {
			return i18n.Errorf("точка %q: ссылка на источник слишком длинная", e.ID)
		}
		su, err := url.Parse(e.Source)
		if err != nil || (su.Scheme != "https" && su.Scheme != "http") || su.Host == "" {
			return i18n.Errorf("точка %q: источник должен быть http(s)-ссылкой", e.ID)
		}
	}
	if e.VerifiedAt != "" {
		if _, err := time.Parse("2006-01-02", e.VerifiedAt); err != nil {
			return i18n.Errorf("точка %q: дата проверки должна быть в формате ГГГГ-ММ-ДД", e.ID)
		}
	}
	if len(e.Note) > 500 || len(e.DisabledReason) > 500 {
		return i18n.Errorf("точка %q: примечание слишком длинное", e.ID)
	}
	return nil
}

func (r *Registry) validateAll(eps []model.Endpoint) error {
	seen := map[string]bool{}
	for _, e := range eps {
		if err := Validate(e, r.policy); err != nil {
			return err
		}
		id := strings.ToLower(strings.TrimSpace(e.ID))
		if seen[id] {
			return i18n.Errorf("повторяющийся id %q", id)
		}
		seen[id] = true
	}
	return nil
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// SortedIDs is a helper for deterministic output in tests and exports.
func SortedIDs(eps []model.Endpoint) []string {
	ids := make([]string, 0, len(eps))
	for _, e := range eps {
		ids = append(ids, e.ID)
	}
	sort.Strings(ids)
	return ids
}
