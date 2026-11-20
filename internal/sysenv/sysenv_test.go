package sysenv

import (
	"encoding/json"
	"runtime"
	"testing"

	"vpncheck/internal/model"
	"vpncheck/internal/sysproxy"
)

func TestIsTunLike(t *testing.T) {
	yes := []struct {
		d string
		t uint32
	}{{"Wintun Userspace Tunnel", 53}, {"WireGuard Tunnel", 53}, {"TAP-Windows Adapter V9", 6}, {"Amnezia Tunnel", 131}, {"Something", 131}, {"WAN Miniport (IKEv2)", 23}}
	for _, c := range yes {
		if !IsTunLike(c.d, c.t) {
			t.Errorf("%q/%d should be tun-like", c.d, c.t)
		}
	}
	no := []struct {
		d string
		t uint32
	}{{"Intel(R) Wi-Fi 7 BE200 320MHz", 71}, {"Realtek PCIe GbE Family Controller", 6}, {"WAN Miniport (IP)", 23}, {"Bluetooth Device (Personal Area Network)", 6}}
	for _, c := range no {
		if IsTunLike(c.d, c.t) {
			t.Errorf("%q/%d should not be tun-like", c.d, c.t)
		}
	}
}

func TestClassifyAndVerdictProxyMode(t *testing.T) {
	procs := map[int]string{100: "v2rayN.exe", 101: "xray.exe", 200: "chrome.exe", 300: "svchost.exe"}
	listeners := []Listener{
		{Addr: "127.0.0.1", Port: 10808, PID: 101},
		{Addr: "127.0.0.1", Port: 10809, PID: 101},
		{Addr: "0.0.0.0", Port: 135, PID: 300},
		{Addr: "127.0.0.1", Port: 8080, PID: 200},
	}
	clients, proxies := classify(procs, listeners)
	if len(clients) != 2 || clients[0].Name != "Xray-core" || clients[1].Name != "v2rayN" {
		t.Fatalf("clients: %+v", clients)
	}
	if len(clients[0].Listening) != 2 || clients[0].Listening[1].Guess != "http" {
		t.Fatalf("xray listeners: %+v", clients[0].Listening)
	}
	if len(proxies) != 3 { // 8080 by chrome on loopback is kept as a guess too
		t.Fatalf("proxies: %+v", proxies)
	}
	p := &Passport{Adapters: []Adapter{{Index: 5, Name: "Wi-Fi", Description: "Intel Wi-Fi", Up: true}},
		DefaultRoute: Route{Known: true, IfIndex: 5, IfName: "Wi-Fi", IfDesc: "Intel Wi-Fi"},
		Proxies:      sysproxy.Hint{Found: true, Suggested: &model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "127.0.0.1:10809"}},
		Clients:      clients, LocalProxies: proxies}
	v := verdict(p)
	if v.Mode != "proxy" || v.SuggestedRoute == nil || v.SuggestedRoute.ProxyAddr != "127.0.0.1:10809" || v.SuggestedRoute.ProxyKind != model.ProxyHTTP {
		t.Fatalf("verdict: %+v", v)
	}
	if v.Confidence != "high" {
		t.Errorf("confidence: %s", v.Confidence)
	}
}

func TestVerdictTunAndNone(t *testing.T) {
	p := &Passport{DefaultRoute: Route{Known: true, IfIndex: 9, IfName: "wg0", IfDesc: "WireGuard Tunnel", ViaTunnel: true}}
	if v := verdict(p); v.Mode != "tun" || v.SuggestedRoute.Mode != model.RouteSystem {
		t.Fatalf("tun verdict: %+v", v)
	}
	p = &Passport{DefaultRoute: Route{Known: true, IfName: "Ethernet", IfDesc: "Realtek"}, Clients: []Client{}, LocalProxies: []Listener{}}
	if v := verdict(p); v.Mode != "none" {
		t.Fatalf("none verdict: %+v", v)
	}
	p = &Passport{DefaultRoute: Route{Known: true, IfName: "Ethernet"}, Clients: []Client{{Name: "WireGuard"}}, LocalProxies: []Listener{}}
	if v := verdict(p); v.Mode != "client-no-proxy" {
		t.Fatalf("client-no-proxy verdict: %+v", v)
	}
}

func TestCollectOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	p := Collect()
	if len(p.Adapters) == 0 {
		t.Fatalf("no adapters: errors=%v", p.Errors)
	}
	if !p.DefaultRoute.Known {
		t.Errorf("default route unknown: %+v", p.DefaultRoute)
	}
	if _, err := json.Marshal(p); err != nil {
		t.Fatal(err)
	}
	t.Logf("verdict: %s (%s); route via %s; clients=%d; proxies=%d; errors=%v", p.Verdict.Title, p.Verdict.Mode, p.DefaultRoute.IfDesc, len(p.Clients), len(p.LocalProxies), p.Errors)
}
