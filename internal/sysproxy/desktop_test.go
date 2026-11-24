package sysproxy

import "testing"

func TestGnomeProxy(t *testing.T) {
	vals := map[string]string{
		"org.gnome.system.proxy mode":           "'manual'\n",
		"org.gnome.system.proxy.http host":      "'127.0.0.1'\n",
		"org.gnome.system.proxy.http port":      "10809\n",
		"org.gnome.system.proxy.https host":     "''\n",
		"org.gnome.system.proxy.https port":     "0\n",
		"org.gnome.system.proxy.socks host":     "'127.0.0.1'\n",
		"org.gnome.system.proxy.socks port":     "10808\n",
		"org.gnome.system.proxy autoconfig-url": "''\n",
	}
	sp := gnomeProxy(func(s, k string) string { return vals[s+" "+k] })
	if !sp.Enabled || sp.Server != "http=127.0.0.1:10809;socks=127.0.0.1:10808" || sp.PAC != "" {
		t.Fatalf("%+v", sp)
	}
	if rc := parseWinINET(sp.Server); rc == nil || rc.ProxyAddr != "127.0.0.1:10809" {
		t.Fatalf("route: %+v", rc)
	}
	vals["org.gnome.system.proxy mode"] = "'none'"
	if sp := gnomeProxy(func(s, k string) string { return vals[s+" "+k] }); sp.Enabled {
		t.Fatal("mode none must be disabled")
	}
}

func TestKDEProxy(t *testing.T) {
	text := "[General]\nfoo=bar\n\n[Proxy Settings]\nProxyType=1\nhttpProxy=http://127.0.0.1 10809\nsocksProxy=socks://127.0.0.1:10808\nhttpsProxy=\n"
	sp := kdeProxy(text)
	if !sp.Enabled || sp.Server != "http=127.0.0.1:10809;socks=127.0.0.1:10808" {
		t.Fatalf("%+v", sp)
	}
	if sp := kdeProxy("[Proxy Settings]\nProxyType=0\nhttpProxy=http://127.0.0.1 3128\n"); sp.Enabled || sp.Server != "http=127.0.0.1:3128" {
		t.Fatalf("off: %+v", sp)
	}
	if sp := kdeProxy("[Proxy Settings]\nProxyType=2\nProxy Config Script=http://wpad/wpad.dat\n"); !sp.Enabled || sp.PAC == "" {
		t.Fatalf("pac: %+v", sp)
	}
}
