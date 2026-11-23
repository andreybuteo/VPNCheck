package server

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

func newTestServer(t *testing.T) (*Server, *atomic.Bool) {
	t.Helper()
	quit := &atomic.Bool{}
	ui := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>t</title>")}}
	s, err := New(Config{UI: ui, OnQuit: func() { quit.Store(true) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	s.hub.heartbeat = 50 * time.Millisecond
	go func() { _ = s.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s, quit
}

func noRedirectClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:     jar,
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func authedClient(t *testing.T, s *Server) (*http.Client, string) {
	t.Helper()
	c := noRedirectClient()
	resp, err := c.Get(s.LaunchURL())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("launch: want 303, got %d", resp.StatusCode)
	}
	resp, err = c.Get(s.BaseURL() + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session info: want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	idx := strings.Index(string(body), `"csrf":"`)
	if idx < 0 {
		t.Fatalf("no csrf in %s", body)
	}
	csrf := string(body[idx+8 : idx+8+64])
	return c, csrf
}

func TestAPIRequiresSession(t *testing.T) {
	s, _ := newTestServer(t)
	c := noRedirectClient()
	resp, err := c.Get(s.BaseURL() + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	// Static UI is served regardless (it shows a "session required" message itself).
	resp, err = c.Get(s.BaseURL() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("index: want 200, got %d", resp.StatusCode)
	}
}

func TestLaunchTokenRejectsWrongToken(t *testing.T) {
	s, _ := newTestServer(t)
	c := noRedirectClient()
	resp, err := c.Get(s.BaseURL() + "/session?t=" + strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	if len(resp.Cookies()) != 0 {
		t.Fatal("cookie must not be set on wrong token")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	s, _ := newTestServer(t)
	c := noRedirectClient()
	resp, err := c.Get(s.LaunchURL())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var found bool
	for _, ck := range resp.Cookies() {
		if ck.Name == cookieName {
			found = true
			if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
				t.Fatalf("cookie attributes wrong: %+v", ck)
			}
		}
	}
	if !found {
		t.Fatal("session cookie not set")
	}
}

func TestQuitRequiresCSRF(t *testing.T) {
	s, quit := newTestServer(t)
	c, csrf := authedClient(t, s)

	req, _ := http.NewRequest(http.MethodPost, s.BaseURL()+"/api/quit", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no csrf: want 403, got %d", resp.StatusCode)
	}
	if quit.Load() {
		t.Fatal("quit must not fire without csrf")
	}

	req, _ = http.NewRequest(http.MethodPost, s.BaseURL()+"/api/quit", nil)
	req.Header.Set(csrfHeader, csrf)
	req.Header.Set("Origin", "https://evil.example")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin: want 403, got %d", resp.StatusCode)
	}
	if quit.Load() {
		t.Fatal("quit must not fire from foreign origin")
	}

	req, _ = http.NewRequest(http.MethodPost, s.BaseURL()+"/api/quit", nil)
	req.Header.Set(csrfHeader, csrf)
	req.Header.Set("Origin", s.BaseURL())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid quit: want 200, got %d", resp.StatusCode)
	}
	deadline := time.Now().Add(time.Second)
	for !quit.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !quit.Load() {
		t.Fatal("OnQuit was not called")
	}
}

func TestForeignHostRejected(t *testing.T) {
	// DNS rebinding: attacker.example resolves to 127.0.0.1 and the browser sends Host: attacker.example:port.
	s, _ := newTestServer(t)
	c, _ := authedClient(t, s)
	req, _ := http.NewRequest(http.MethodGet, s.BaseURL()+"/api/session", nil)
	req.Host = "attacker.example:" + itoa(s.Port())
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestCrossSiteFetchRejected(t *testing.T) {
	s, _ := newTestServer(t)
	c, _ := authedClient(t, s)
	req, _ := http.NewRequest(http.MethodGet, s.BaseURL()+"/api/session", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("no CORS headers must ever be emitted")
	}
}

func TestPreflightRejected(t *testing.T) {
	s, _ := newTestServer(t)
	c := noRedirectClient()
	req, _ := http.NewRequest(http.MethodOptions, s.BaseURL()+"/api/quit", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		t.Fatalf("preflight must fail, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("no CORS headers must ever be emitted")
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _ := newTestServer(t)
	c := noRedirectClient()
	resp, err := c.Get(s.BaseURL() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Cache-Control"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
}

func TestSSERequiresSessionAndDelivers(t *testing.T) {
	s, _ := newTestServer(t)
	anon := noRedirectClient()
	resp, err := anon.Get(s.BaseURL() + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anon sse: want 401, got %d", resp.StatusCode)
	}

	c, _ := authedClient(t, s)
	c.Timeout = 0
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL()+"/api/events", nil)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sse: want 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type %q", ct)
	}
	// Wait until subscribed, then publish.
	for s.hub.ClientCount() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	s.hub.Publish("progress", map[string]any{"step": 1})
	rd := bufio.NewReader(resp.Body)
	var got string
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v (so far %q)", err, got)
		}
		got += line
		if strings.Contains(got, `event: progress`) && strings.Contains(got, `"step":1`) {
			break
		}
	}
}

func TestUnknownStaticIs404(t *testing.T) {
	s, _ := newTestServer(t)
	c := noRedirectClient()
	resp, err := c.Get(s.BaseURL() + "/missing.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestSuccessfulSessionRotatesRelaunchToken(t *testing.T) {
	s, _ := newTestServer(t)
	first := s.LaunchURL()
	c := noRedirectClient()
	for _, step := range []struct {
		url  string
		want int
	}{{first, 303}, {first, 403}} {
		resp, err := c.Get(step.url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != step.want {
			t.Fatalf("status %d, want %d", resp.StatusCode, step.want)
		}
	}
	authedClient(t, s)
}
