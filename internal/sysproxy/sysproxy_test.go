package sysproxy

import (
	"testing"

	"vpncheck/internal/model"
)

func TestParseWinINET(t *testing.T) {
	if rc := parseWinINET("127.0.0.1:10809"); rc == nil || rc.ProxyKind != model.ProxyHTTP || rc.ProxyAddr != "127.0.0.1:10809" {
		t.Fatalf("plain: %+v", rc)
	}
	if rc := parseWinINET("http=proxy.corp:3128;https=proxy.corp:3129;socks=proxy.corp:1080"); rc == nil || rc.ProxyAddr != "proxy.corp:3129" {
		t.Fatalf("per-protocol: %+v", rc)
	}
	if rc := parseWinINET("socks=127.0.0.1:1080"); rc == nil || rc.ProxyKind != model.ProxySOCKS5 {
		t.Fatalf("socks: %+v", rc)
	}
	if rc := parseWinINET("user:pw@proxy:8080"); rc != nil {
		t.Fatal("credentials must not be suggested")
	}
	if rc := parseWinINET("garbage"); rc != nil {
		t.Fatal("garbage must not be suggested")
	}
}

func TestParseEnvProxy(t *testing.T) {
	clean, creds, rc := parseEnvProxy("http://user:secret@10.0.0.1:3128")
	if creds != true || clean == "" || rc != nil || contains(clean, "secret") {
		t.Fatalf("creds: clean=%q creds=%v rc=%+v", clean, creds, rc)
	}
	clean, creds, rc = parseEnvProxy("socks5://127.0.0.1:1080")
	if creds || rc == nil || rc.ProxyKind != model.ProxySOCKS5 || rc.ProxyAddr != "127.0.0.1:1080" || clean != "socks5://127.0.0.1:1080" {
		t.Fatalf("socks5: clean=%q rc=%+v", clean, rc)
	}
	_, _, rc = parseEnvProxy("http://127.0.0.1:10809")
	if rc == nil || rc.ProxyKind != model.ProxyHTTP {
		t.Fatalf("http: %+v", rc)
	}
	clean, _, rc = parseEnvProxy("localhost,127.0.0.1,::1,.local")
	if rc != nil || clean == "" {
		t.Fatalf("no_proxy list: %q %+v", clean, rc)
	}
}

func TestDetectDoesNotPanic(t *testing.T) {
	h := Detect()
	_ = h.Short()
	for k, v := range h.Env {
		if contains(v, "@") && !contains(v, "[скрыто]") {
			t.Errorf("%s leaks credentials: %s", k, v)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
