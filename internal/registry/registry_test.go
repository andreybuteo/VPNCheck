package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpncheck/internal/guard"
	"vpncheck/internal/model"
	"vpncheck/internal/store"
)

func newReg(t *testing.T) (*Registry, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, info := Load(st)
	if info.Found || info.Corrupt || info.Invalid != "" {
		t.Fatalf("fresh load should use defaults: %+v", info)
	}
	return r, st
}

func TestDefaultsAreValidAndDocumented(t *testing.T) {
	eps := Defaults()
	if len(eps) < 25 || len(eps) > 35 {
		t.Fatalf("spec asks for ~25–35 endpoints, got %d", len(eps))
	}
	seen := map[string]bool{}
	enabled := 0
	for _, e := range eps {
		if err := Validate(e, guard.Default()); err != nil {
			t.Errorf("default endpoint invalid: %v", err)
		}
		if seen[e.ID] {
			t.Errorf("duplicate id %s", e.ID)
		}
		seen[e.ID] = true
		if e.Source == "" || e.VerifiedAt == "" {
			t.Errorf("%s: source and verifiedAt are mandatory for built-in points", e.ID)
		}
		if !e.Enabled && e.DisabledReason == "" {
			t.Errorf("%s: disabled without a reason", e.ID)
		}
		if e.Kind == model.KindHTTPS && len(e.ExpectedStatuses) == 0 {
			t.Errorf("%s: https point without expected statuses", e.ID)
		}
		if e.Custom {
			t.Errorf("%s: built-in point marked custom", e.ID)
		}
		if e.Enabled {
			enabled++
		}
	}
	if enabled < 25 {
		t.Errorf("want at least 25 enabled points, got %d", enabled)
	}
}

func TestValidateRejectsBadEndpoints(t *testing.T) {
	base := model.Endpoint{ID: "custom-1", GroupID: "custom", Group: "Свои", Label: "x", Host: "example-service.com", Kind: model.KindTLS, Enabled: true}
	cases := []struct {
		name string
		mod  func(e *model.Endpoint)
		want string
	}{
		{"bad id", func(e *model.Endpoint) { e.ID = "Bad ID!" }, "id"},
		{"loopback host", func(e *model.Endpoint) { e.Host = "127.0.0.1" }, "хост"},
		{"private host", func(e *model.Endpoint) { e.Host = "10.0.0.1" }, "хост"},
		{"metadata", func(e *model.Endpoint) { e.Host = "169.254.169.254" }, "хост"},
		{"local tld", func(e *model.Endpoint) { e.Host = "nas.local" }, "хост"},
		{"wildcard", func(e *model.Endpoint) { e.Host = "*.googlevideo.com" }, "хост"},
		{"tls with url", func(e *model.Endpoint) { e.URL = "https://example-service.com/" }, "URL не задаётся"},
		{"https no url", func(e *model.Endpoint) { e.Kind = model.KindHTTPS }, "нужен URL"},
		{"http scheme", func(e *model.Endpoint) { e.Kind = model.KindHTTPS; e.URL = "http://example-service.com/" }, "https"},
		{"credentials in url", func(e *model.Endpoint) { e.Kind = model.KindHTTPS; e.URL = "https://user:pw@example-service.com/" }, "логин"},
		{"port 8443", func(e *model.Endpoint) { e.Kind = model.KindHTTPS; e.URL = "https://example-service.com:8443/" }, "443"},
		{"host mismatch", func(e *model.Endpoint) { e.Kind = model.KindHTTPS; e.URL = "https://other.example-service.com/" }, "не совпадает"},
		{"bad status", func(e *model.Endpoint) { e.ExpectedStatuses = []int{99} }, "статус"},
		{"bad kind", func(e *model.Endpoint) { e.Kind = "icmp" }, "тип"},
		{"forbidden header", func(e *model.Endpoint) {
			e.Kind = model.KindHTTPS
			e.URL = "https://example-service.com/"
			e.Headers = map[string]string{"Authorization": "Bearer x"}
		}, "не разрешён"},
		{"bad source", func(e *model.Endpoint) { e.Source = "ftp://x" }, "источник"},
		{"bad date", func(e *model.Endpoint) { e.VerifiedAt = "13.09.2026" }, "дата"},
	}
	for _, c := range cases {
		e := base
		c.mod(&e)
		err := Validate(e, guard.Default())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
	good := base
	good.Kind = model.KindHTTPS
	good.URL = "https://example-service.com:443/status?x=1"
	good.Headers = map[string]string{"accept": "application/json"}
	good.ExpectedStatuses = []int{200, 204}
	if err := Validate(good, guard.Default()); err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
}

func TestEnableDisablePersists(t *testing.T) {
	r, st := newReg(t)
	if err := r.SetEnabled("openai-cdn", true); err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled("github-web", false); err != nil {
		t.Fatal(err)
	}
	r2, info := Load(st)
	if !info.Found || info.Corrupt || info.Invalid != "" {
		t.Fatalf("reload: %+v", info)
	}
	if e, _ := r2.Get("openai-cdn"); !e.Enabled {
		t.Error("openai-cdn should be enabled after reload")
	}
	if e, _ := r2.Get("github-web"); e.Enabled {
		t.Error("github-web should be disabled after reload")
	}
}

func TestCustomEndpointsLifecycle(t *testing.T) {
	r, _ := newReg(t)
	custom := model.Endpoint{ID: "my-site", GroupID: "mine", Group: "Мои", Label: "сайт", Host: "www.example-mine.com", Kind: model.KindTLS, Enabled: true}
	if err := r.Upsert(custom); err != nil {
		t.Fatal(err)
	}
	got, ok := r.Get("my-site")
	if !ok || !got.Custom || got.VerifiedAt == "" {
		t.Fatalf("custom not stored properly: %+v", got)
	}
	// Built-ins cannot be edited or deleted.
	b, _ := r.Get("github-web")
	b.Host = "evil.example-mine.com"
	if err := r.Upsert(b); err == nil {
		t.Fatal("editing a built-in must fail")
	}
	if err := r.Delete("github-web"); err == nil {
		t.Fatal("deleting a built-in must fail")
	}
	if err := r.Delete("my-site"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("my-site"); ok {
		t.Fatal("custom should be gone")
	}
	// Invalid custom is rejected and leaves the list unchanged.
	n := len(r.List())
	bad := custom
	bad.Host = "192.168.0.1"
	if err := r.Upsert(bad); err == nil {
		t.Fatal("private host must be rejected")
	}
	if len(r.List()) != n {
		t.Fatal("rejected upsert must not change the list")
	}
}

func TestImportValidatesEverythingBeforeApplying(t *testing.T) {
	r, st := newReg(t)
	before := r.List()

	// A document with one bad endpoint must be rejected entirely.
	doc := Document{SchemaVersion: 1, Endpoints: []model.Endpoint{
		{ID: "ok-1", GroupID: "g", Group: "G", Host: "a.example-import.com", Kind: model.KindTLS, Enabled: true},
		{ID: "bad-1", GroupID: "g", Group: "G", Host: "localhost", Kind: model.KindTLS, Enabled: true},
	}}
	data, _ := json.Marshal(doc)
	if err := r.Import(data); err == nil {
		t.Fatal("import with an invalid endpoint must fail")
	}
	if len(r.List()) != len(before) {
		t.Fatal("failed import must not change the registry")
	}
	if _, err := os.Stat(filepath.Join(st.Dir(), fileName)); err == nil {
		t.Fatal("failed import must not write the registry file")
	}

	// Wrong schema version.
	doc.SchemaVersion = 99
	data, _ = json.Marshal(doc)
	if err := r.Import(data); err == nil || !strings.Contains(err.Error(), "схемы") {
		t.Fatalf("want schema error, got %v", err)
	}

	// Garbage.
	if err := r.Import([]byte("{nope")); err == nil {
		t.Fatal("garbage import must fail")
	}

	// A valid import that disables a built-in and adds a custom point; the
	// built-in's identity comes from the embedded profile, not the file.
	tampered, _ := r.Get("github-api")
	tampered.Enabled = false
	tampered.URL = "https://api.github.com/evil"
	doc = Document{SchemaVersion: 1, Endpoints: []model.Endpoint{
		tampered,
		{ID: "ok-1", GroupID: "g", Group: "G", Host: "a.example-import.com", Kind: model.KindTLS, Enabled: true},
	}}
	data, _ = json.Marshal(doc)
	if err := r.Import(data); err != nil {
		t.Fatal(err)
	}
	g, _ := r.Get("github-api")
	if g.Enabled || g.URL != "https://api.github.com/" {
		t.Fatalf("built-in identity must be preserved on import: %+v", g)
	}
	if c, ok := r.Get("ok-1"); !ok || !c.Custom {
		t.Fatal("custom endpoint from import missing")
	}
	// Built-ins missing from the file are merged back with default state.
	if _, ok := r.Get("github-web"); !ok {
		t.Fatal("missing built-ins must be merged back")
	}
	// Export round-trips.
	out, err := r.Export()
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := json.Unmarshal(out, &back); err != nil || back.SchemaVersion != 1 || len(back.Endpoints) != len(r.List()) {
		t.Fatalf("export broken: %v", err)
	}
}

func TestCorruptRegistryFileFallsBackToDefaults(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	os.WriteFile(filepath.Join(st.Dir(), fileName), []byte("{broken"), 0o600)
	r, info := Load(st)
	if !info.Corrupt {
		t.Fatalf("corrupt not reported: %+v", info)
	}
	if len(r.List()) != len(Defaults()) {
		t.Fatal("defaults expected after corruption")
	}
	// A parseable but invalid file is reported too and left in place.
	os.WriteFile(filepath.Join(st.Dir(), fileName), []byte(`{"schemaVersion":1,"endpoints":[{"id":"x","groupId":"g","group":"G","host":"localhost","kind":"tls","enabled":true}]}`), 0o600)
	r, info = Load(st)
	if info.Invalid == "" || len(r.List()) != len(Defaults()) {
		t.Fatalf("invalid file should fall back to defaults with a reason: %+v", info)
	}
}

func TestReset(t *testing.T) {
	r, _ := newReg(t)
	_ = r.Upsert(model.Endpoint{ID: "tmp", GroupID: "g", Group: "G", Host: "x.example-reset.com", Kind: model.KindTLS, Enabled: true})
	if err := r.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Get("tmp"); ok {
		t.Fatal("reset must drop custom points")
	}
}

func TestSettingsSurviveFailedRegistryWrite(t *testing.T) {
	r, st := newReg(t)
	ep := r.List()[0]
	data, _ := r.Export()
	if err := r.Import(append(data, '{')); err == nil {
		t.Fatal("trailing data accepted")
	}
	if err := os.Mkdir(filepath.Join(st.Dir(), fileName), 0700); err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled(ep.ID, !ep.Enabled); err == nil {
		t.Fatal("expected write failure")
	}
	if got, _ := r.Get(ep.ID); got.Enabled != ep.Enabled {
		t.Fatal("failed write changed registry")
	}

}
