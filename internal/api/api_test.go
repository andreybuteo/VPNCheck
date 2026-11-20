package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
	"vpncheck/internal/probe"
	"vpncheck/internal/registry"
	"vpncheck/internal/runner"
	"vpncheck/internal/server"
	"vpncheck/internal/speed"
	"vpncheck/internal/store"
)

type stubProber struct{ opts probe.Options }

func (s stubProber) Probe(_ context.Context, ep model.Endpoint) model.ProbeResult {
	ms := 50.0
	return model.ProbeResult{EndpointID: ep.ID, GroupID: ep.GroupID, Host: ep.Host, Kind: ep.Kind, Attempt: 1, StartedAt: time.Now(),
		Timings: model.Timings{TLSReadyMs: &ms}, Transport: model.Transport{OK: true, CertVerified: true}}
}
func (s stubProber) FetchSmall(context.Context, string, int64) (int, []byte, error) {
	return 500, nil, nil
}

type client struct {
	t    *testing.T
	c    *http.Client
	base string
	csrf string
}

func newClient(t *testing.T) (*client, *store.Store) {
	t.Helper()
	st, _ := store.Open(t.TempDir())
	reg, regInfo := registry.Load(st)
	lim := limiter.New(st, time.Now)
	lim.RunCooldown = 0
	lim.GroupSpacing = 0
	ui := fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}}
	srv, err := server.New(server.Config{UI: ui, OnQuit: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	run := runner.New(runner.Deps{Store: st, Registry: reg, Limiter: lim, Publish: func(string, any) {},
		NewProber: func(o probe.Options) runner.Prober { return stubProber{opts: o} }})
	settings, sInfo, _ := st.LoadSettings()
	sp := speed.NewRunner(speed.Deps{Store: st, Limiter: lim, NewMeter: func(model.RouteConfig) speed.Meter { return slowMeter{} }})
	Mount(Deps{Server: srv, Store: st, Registry: reg, RegistryInfo: regInfo, Limiter: lim, Runner: run, Speed: sp, Settings: settings, SettingsInfo: sInfo})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Get(srv.LaunchURL())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cl := &client{t: t, c: hc, base: srv.BaseURL()}
	var info struct {
		CSRF string `json:"csrf"`
	}
	cl.do("GET", "/api/session", nil, &info)
	cl.csrf = info.CSRF
	return cl, st
}

func (c *client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if method != "GET" {
		req.Header.Set("X-VPNCheck-CSRF", c.csrf)
		req.Header.Set("Origin", c.base)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil {
		if raw, ok := out.(*[]byte); ok {
			*raw = data
		} else if err := json.Unmarshal(data, out); err != nil {
			c.t.Fatalf("%s %s: bad json %v: %s", method, path, err, data)
		}
	}
	return resp.StatusCode
}

func TestStateAndSettings(t *testing.T) {
	cl, _ := newClient(t)
	var state map[string]any
	if code := cl.do("GET", "/api/state", nil, &state); code != 200 {
		t.Fatalf("state: %d", code)
	}
	for _, k := range []string{"app", "settings", "registry", "limiter", "current", "sysproxy", "history", "limits"} {
		if _, ok := state[k]; !ok {
			t.Errorf("state missing %s", k)
		}
	}
	var errBody map[string]any
	if code := cl.do("PUT", "/api/settings", map[string]any{"theme": "neon", "route": map[string]any{"mode": "system"}, "ipFamily": "auto", "mode": "fast", "slowThresholdMs": 1500}, &errBody); code != 400 {
		t.Fatalf("invalid theme accepted: %d %v", code, errBody)
	}
	if code := cl.do("PUT", "/api/settings", map[string]any{"theme": "dark", "route": map[string]any{"mode": "proxy", "proxyKind": "http", "proxyAddr": "bad"}, "ipFamily": "auto", "mode": "fast", "slowThresholdMs": 1500}, &errBody); code != 400 {
		t.Fatalf("invalid proxy accepted: %d", code)
	}
	var saved model.Settings
	if code := cl.do("PUT", "/api/settings", map[string]any{"profileName": " VPN — DE ", "theme": "light", "route": map[string]any{"mode": "proxy", "proxyKind": "socks5", "proxyAddr": "127.0.0.1:1080"}, "ipFamily": "ipv4", "mode": "fast", "slowThresholdMs": 900, "showExternalIp": true, "selectedEndpoints": []string{}, "stabilityEndpoints": []string{}}, &saved); code != 200 {
		t.Fatalf("valid settings rejected: %d", code)
	}
	if saved.ProfileName != "VPN — DE" || saved.Theme != "light" || saved.Route.ProxyAddr != "127.0.0.1:1080" || saved.SlowThresholdMs != 900 {
		t.Fatalf("saved: %+v", saved)
	}
	if saved.RunCooldownSec != 60 {
		t.Fatalf("missing runCooldownSec must default to 60, got %d", saved.RunCooldownSec)
	}
	for _, bad := range []int{5, 1801, -1} {
		if code := cl.do("PUT", "/api/settings", map[string]any{"theme": "dark", "route": map[string]any{"mode": "system"}, "ipFamily": "auto", "mode": "fast", "slowThresholdMs": 1500, "runCooldownSec": bad}, &errBody); code != 400 {
			t.Fatalf("runCooldownSec %d accepted: %d", bad, code)
		}
	}
	if code := cl.do("PUT", "/api/settings", map[string]any{"theme": "dark", "route": map[string]any{"mode": "system"}, "ipFamily": "auto", "mode": "fast", "slowThresholdMs": 1500, "runCooldownSec": 20}, &saved); code != 200 || saved.RunCooldownSec != 20 {
		t.Fatalf("runCooldownSec 20 rejected: %d %+v", code, saved)
	}
	var st2 map[string]any
	cl.do("GET", "/api/state", nil, &st2)
	if got := st2["limits"].(map[string]any)["cooldownSec"]; got != float64(20) {
		t.Fatalf("limits.cooldownSec after change = %v", got)
	}
	// Unknown fields rejected (no silent misconfiguration).
	if code := cl.do("PUT", "/api/settings", `{"theme":"dark","route":{"mode":"system"},"ipFamily":"auto","mode":"fast","slowThresholdMs":1,"bogus":1}`, &errBody); code != 400 {
		t.Fatalf("unknown field accepted: %d", code)
	}
}

func TestRunLifecycleHistoryExportCompare(t *testing.T) {
	cl, _ := newClient(t)
	var started struct {
		Run model.RunSummary `json:"run"`
	}
	if code := cl.do("POST", "/api/run", map[string]any{"profileName": "A", "mode": "fast", "route": map[string]any{"mode": "system"}, "ipFamily": "auto", "endpointIds": []string{"github-web", "github-api"}}, &started); code != 202 {
		t.Fatalf("start: %d", code)
	}
	// Wait for completion via /api/run/current.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var cur map[string]any
		cl.do("GET", "/api/run/current", nil, &cur)
		prog := cur["progress"].(map[string]any)
		if prog["status"] != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("run did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	var hist []model.RunSummary
	cl.do("GET", "/api/history", nil, &hist)
	if len(hist) != 1 || hist[0].ID != started.Run.ID {
		t.Fatalf("history: %+v", hist)
	}
	var view map[string]any
	if code := cl.do("GET", "/api/history/"+started.Run.ID, nil, &view); code != 200 {
		t.Fatalf("history get: %d", code)
	}
	if groups := view["groups"].([]any); len(groups) != 1 {
		t.Fatalf("groups: %v", groups)
	}
	var raw []byte
	if code := cl.do("GET", "/api/export/"+started.Run.ID+"/json", nil, &raw); code != 200 || !bytes.Contains(raw, []byte(`"schemaVersion": 1`)) {
		t.Fatalf("json export: %d %s", code, raw)
	}
	if code := cl.do("GET", "/api/export/"+started.Run.ID+"/csv", nil, &raw); code != 200 || !bytes.HasPrefix(raw, []byte("\xEF\xBB\xBF")) {
		t.Fatalf("csv export: %d", code)
	}
	if code := cl.do("GET", "/api/summary/"+started.Run.ID, nil, &raw); code != 200 || !bytes.Contains(raw, []byte("краткий итог")) {
		t.Fatalf("summary: %d %s", code, raw)
	}
	// Second run and compare.
	var started2 struct {
		Run model.RunSummary `json:"run"`
	}
	if code := cl.do("POST", "/api/run", map[string]any{"profileName": "B", "mode": "fast", "route": map[string]any{"mode": "system"}, "ipFamily": "auto", "endpointIds": []string{"github-web"}}, &started2); code != 202 {
		t.Fatalf("start 2: %d", code)
	}
	time.Sleep(150 * time.Millisecond)
	var cmp map[string]any
	if code := cl.do("GET", "/api/compare?a="+started.Run.ID+"&b="+started2.Run.ID, nil, &cmp); code != 200 {
		t.Fatalf("compare: %d", code)
	}
	if rows := cmp["rows"].([]any); len(rows) != 1 {
		t.Fatalf("compare rows: %v", rows)
	}
	if code := cl.do("GET", "/api/compare?a=nope&b="+started.Run.ID, nil, &cmp); code != 400 && code != 404 {
		t.Fatalf("compare missing: %d", code)
	}
	if code := cl.do("DELETE", "/api/history/"+started2.Run.ID, nil, &cmp); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if code := cl.do("DELETE", "/api/history/..%2Fsettings", nil, &raw); code == 200 {
		t.Fatal("path traversal id must be rejected")
	}
}

func TestRunValidationAndCancel(t *testing.T) {
	cl, _ := newClient(t)
	var e map[string]any
	if code := cl.do("POST", "/api/run", map[string]any{"mode": "stability", "route": map[string]any{"mode": "system"}, "ipFamily": "auto"}, &e); code != 400 {
		t.Fatalf("stability without endpoints: %d", code)
	}
	if code := cl.do("POST", "/api/run", map[string]any{"mode": "fast", "route": map[string]any{"mode": "proxy", "proxyKind": "http", "proxyAddr": "x"}, "ipFamily": "auto"}, &e); code != 400 {
		t.Fatalf("bad proxy: %d", code)
	}
	var c map[string]any
	if code := cl.do("POST", "/api/run/cancel", nil, &c); code != 200 || c["cancelled"] != false {
		t.Fatalf("cancel without run: %d %v", code, c)
	}
}

func TestRegistryEndpoints(t *testing.T) {
	cl, _ := newClient(t)
	var res map[string]any
	if code := cl.do("PUT", "/api/registry/github-web/enabled", map[string]any{"enabled": false}, &res); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if code := cl.do("POST", "/api/registry", map[string]any{"host": "10.0.0.1", "kind": "tls", "enabled": true}, &res); code != 400 {
		t.Fatalf("private custom host accepted: %d", code)
	}
	if code := cl.do("POST", "/api/registry", map[string]any{"host": "www.example-custom.com", "label": "Мой", "kind": "https", "url": "https://www.example-custom.com/health", "expectedStatuses": []int{200}, "enabled": true}, &res); code != 200 {
		t.Fatalf("custom add: %d %v", code, res)
	}
	found := false
	for _, e := range res["endpoints"].([]any) {
		m := e.(map[string]any)
		if m["id"] == "custom-www-example-custom-com" && m["custom"] == true {
			found = true
		}
	}
	if !found {
		t.Fatal("custom endpoint missing")
	}
	if code := cl.do("DELETE", "/api/registry/github-web", nil, &res); code != 400 {
		t.Fatalf("deleting builtin: %d", code)
	}
	if code := cl.do("DELETE", "/api/registry/custom-www-example-custom-com", nil, &res); code != 200 {
		t.Fatalf("deleting custom: %d", code)
	}
	if code := cl.do("POST", "/api/registry/import", `{"schemaVersion":1,"endpoints":[{"id":"x","groupId":"g","group":"G","host":"localhost","kind":"tls","enabled":true}]}`, &res); code != 400 {
		t.Fatalf("bad import accepted: %d", code)
	}
	var raw []byte
	if code := cl.do("GET", "/api/registry/export", nil, &raw); code != 200 || !bytes.Contains(raw, []byte(`"schemaVersion": 1`)) {
		t.Fatalf("registry export: %d", code)
	}
	if code := cl.do("POST", "/api/registry/reset", nil, &res); code != 200 {
		t.Fatalf("reset: %d", code)
	}
}
