package diag

import (
	"strings"
	"testing"

	"vpncheck/internal/model"
)

var sys = model.RouteConfig{Mode: model.RouteSystem}
var prx = model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "127.0.0.1:10809"}

func ep(id, group, host string) model.Endpoint {
	return model.Endpoint{ID: id, GroupID: group, Group: strings.ToUpper(group), Host: host, Kind: model.KindHTTPS}
}

func okRes(id, host string, route model.RouteConfig) model.ProbeResult {
	ms := 100.0
	return model.ProbeResult{EndpointID: id, GroupID: "g", Host: host, Kind: model.KindHTTPS, Attempt: 1, Route: route,
		Timings: model.Timings{TLSReadyMs: &ms}, Transport: model.Transport{OK: true}, HTTP: &model.HTTPResult{Status: 200},
		Outcome: model.Outcome{Code: "http_expected", Level: model.LevelOK, Label: "Контрольный ресурс доступен (200)"}}
}

func failRes(id, host string, route model.RouteConfig, stage model.Stage, kind model.ErrorKind) model.ProbeResult {
	return model.ProbeResult{EndpointID: id, GroupID: "g", Host: host, Kind: model.KindHTTPS, Attempt: 1, Route: route,
		Transport: model.Transport{OK: false, FailedStage: stage, ErrorKind: kind, ErrorText: string(kind)},
		Outcome:   model.Outcome{Code: "x", Level: model.LevelError, Label: "ошибка"}}
}

func TestGeoBlockWins(t *testing.T) {
	r := okRes("a", "api.openai.com", prx)
	r.HTTP = &model.HTTPResult{Status: 403, GeoBlocked: true, GeoSignature: "unsupported_country_region_territory"}
	r.Outcome = model.Outcome{Code: "http_403", Level: model.LevelWarn}
	run := &model.Run{Endpoints: []model.Endpoint{ep("a", "g", "api.openai.com")}, Results: []model.ProbeResult{r}}
	v := Analyze(run, Context{PrimaryRoute: prx, ExitCountry: "RU"})
	if len(v) != 1 || v[0].Code != "geo_block" || v[0].Confidence != "high" || !strings.Contains(strings.Join(v[0].Evidence, " "), "RU") {
		t.Fatalf("%+v", v)
	}
}

func TestDirectBlockedProxyOK(t *testing.T) {
	run := &model.Run{Endpoints: []model.Endpoint{ep("a", "g", "chatgpt.com"), ep("b", "g", "api.openai.com")}, Results: []model.ProbeResult{
		failRes("a", "chatgpt.com", sys, model.StageTCP, model.ErrTimeout), okRes("a", "chatgpt.com", prx),
		failRes("b", "api.openai.com", sys, model.StageTLS, model.ErrReset), okRes("b", "api.openai.com", prx),
	}}
	v := Analyze(run, Context{PrimaryRoute: sys, AltRoute: &prx, EnvMode: "proxy"})
	if v[0].Code != "direct_blocked_proxy_ok" || len(v[0].Evidence) != 2 {
		t.Fatalf("%+v", v[0])
	}
	// Reverse: proxy selected, direct works → route_dependent ok.
	v = Analyze(run, Context{PrimaryRoute: prx, AltRoute: &sys})
	if v[0].Code != "route_dependent" || v[0].Level != model.LevelOK {
		t.Fatalf("%+v", v[0])
	}
}

func TestTransportKinds(t *testing.T) {
	cases := []struct {
		stage model.Stage
		kind  model.ErrorKind
		code  string
	}{
		{model.StageTLS, model.ErrReset, "dpi_reset"},
		{model.StageTCP, model.ErrTimeout, "drop_timeout"},
		{model.StageDNS, model.ErrDNS, "dns_fail"},
		{model.StageTCP, model.ErrRefused, "refused"},
		{model.StageDNS, model.ErrBlockedAddr, "dns_spoof"},
		{model.StageTCP, model.ErrProxy, "proxy_down"},
		{model.StageTLS, model.ErrTLSCert, "tls_intercept"},
	}
	for _, c := range cases {
		run := &model.Run{Endpoints: []model.Endpoint{ep("a", "g", "h.example.com")}, Results: []model.ProbeResult{failRes("a", "h.example.com", sys, c.stage, c.kind)}}
		v := Analyze(run, Context{PrimaryRoute: sys})
		if v[0].Code != c.code {
			t.Errorf("%s/%s: want %s got %s", c.stage, c.kind, c.code, v[0].Code)
		}
	}
}

func TestOKAndHTTPLevels(t *testing.T) {
	run := &model.Run{Endpoints: []model.Endpoint{ep("a", "g", "a.example.com")}, Results: []model.ProbeResult{okRes("a", "a.example.com", sys)}}
	if v := Analyze(run, Context{PrimaryRoute: sys}); v[0].Code != "ok" || v[0].Level != model.LevelOK {
		t.Fatalf("%+v", v[0])
	}
	r := okRes("a", "a.example.com", sys)
	r.HTTP.Status = 503
	r.Outcome = model.Outcome{Code: "http_5xx", Level: model.LevelWarn}
	run.Results = []model.ProbeResult{r}
	if v := Analyze(run, Context{PrimaryRoute: sys}); v[0].Code != "service_error" {
		t.Fatalf("%+v", v[0])
	}
	r.HTTP = &model.HTTPResult{Status: 403, Captcha: true}
	r.Outcome = model.Outcome{Code: "captcha", Level: model.LevelWarn}
	run.Results = []model.ProbeResult{r}
	if v := Analyze(run, Context{PrimaryRoute: sys}); v[0].Code != "ip_reputation" {
		t.Fatalf("%+v", v[0])
	}
	skipped := model.ProbeResult{EndpointID: "a", Skipped: true, Route: sys}
	run.Results = []model.ProbeResult{skipped}
	if v := Analyze(run, Context{PrimaryRoute: sys}); v[0].Code != "not_probed" {
		t.Fatalf("%+v", v[0])
	}
}

func TestGeoBlockOnlyDirectRouteIsRoutingAdvice(t *testing.T) {
	bad := okRes("a", "api.openai.com", sys)
	bad.HTTP = &model.HTTPResult{Status: 403, GeoBlocked: true, GeoSignature: "unsupported_country_region_territory"}
	bad.Outcome = model.Outcome{Code: "http_403", Level: model.LevelWarn, Label: "Запрос отклонён (403)"}
	good := okRes("a", "api.openai.com", prx)
	good.Attempt = 2
	run := &model.Run{Endpoints: []model.Endpoint{ep("a", "g", "api.openai.com")}, Results: []model.ProbeResult{bad, good}}
	v := Analyze(run, Context{PrimaryRoute: sys, AltRoute: &prx})
	if v[0].Code != "geo_block_route" || !strings.Contains(v[0].Advice, "TUN") || len(v[0].Evidence) != 2 {
		t.Fatalf("%+v", v[0])
	}
}
