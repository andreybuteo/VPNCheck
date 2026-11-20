package classify

import (
	"strings"
	"testing"
	"time"

	"vpncheck/internal/model"
)

func f(v float64) *float64 { return &v }

func httpsRes(status int, extra func(h *model.HTTPResult)) model.ProbeResult {
	r := model.ProbeResult{
		Kind:      model.KindHTTPS,
		Transport: model.Transport{OK: true, CertVerified: true},
		Timings:   model.Timings{TLSReadyMs: f(300), TTFBMs: f(450)},
		HTTP:      &model.HTTPResult{Status: status, Proto: "HTTP/2.0"},
	}
	if extra != nil {
		extra(r.HTTP)
	}
	return r
}

func failRes(stage model.Stage, kind model.ErrorKind) model.ProbeResult {
	return model.ProbeResult{Kind: model.KindTLS, Transport: model.Transport{OK: false, FailedStage: stage, ErrorKind: kind, ErrorText: "tech detail"}}
}

func TestHTTPStatusTable(t *testing.T) {
	th := Thresholds{SlowMs: 1500}
	ep200 := model.Endpoint{ExpectedStatuses: []int{200}}
	ep401 := model.Endpoint{ExpectedStatuses: []int{401}}
	cases := []struct {
		name   string
		r      model.ProbeResult
		ep     model.Endpoint
		code   string
		level  model.Level
		inText string
	}{
		{"200 expected", httpsRes(200, nil), ep200, "http_expected", model.LevelOK, "доступен"},
		{"301 redirect", httpsRes(301, func(h *model.HTTPResult) { h.Location = "https://x.example/…" }), ep200, "http_redirect", model.LevelWarn, "Перенаправление"},
		{"401 expected (API without key)", httpsRes(401, nil), ep401, "http_expected", model.LevelOK, "требуется авторизация"},
		{"401 unexpected", httpsRes(401, nil), ep200, "http_401", model.LevelWarn, "требуется авторизация"},
		{"403", httpsRes(403, nil), ep200, "http_403", model.LevelWarn, "причина не установлена"},
		{"403 captcha", httpsRes(403, func(h *model.HTTPResult) { h.Captcha = true }), ep200, "captcha", model.LevelWarn, "требуется проверка"},
		{"404", httpsRes(404, nil), ep200, "http_unexpected", model.LevelWarn, "не подходит"},
		{"405", httpsRes(405, nil), ep200, "http_unexpected", model.LevelWarn, "не подходит"},
		{"429 default", httpsRes(429, nil), ep200, "http_429", model.LevelWarn, "15 минут"},
		{"429 with reset", httpsRes(429, func(h *model.HTTPResult) { h.RateLimitReset = time.Now().Add(time.Hour).UTC().Format(time.RFC3339) }), ep200, "http_429", model.LevelWarn, "повтор после"},
		{"500", httpsRes(500, nil), ep200, "http_5xx", model.LevelWarn, "TLS были успешны"},
		{"200 but 401 expected", httpsRes(200, nil), ep401, "http_unexpected", model.LevelWarn, "ожидался другой"},
	}
	for _, c := range cases {
		o := Probe(&c.r, c.ep, th)
		if o.Code != c.code || o.Level != c.level || !strings.Contains(o.Label, c.inText) {
			t.Errorf("%s: got %+v", c.name, o)
		}
	}
	// 404 must never be described as a VPN failure and 401 never as "works fully".
	o := Probe(&cases[6].r, ep200, th)
	if strings.Contains(strings.ToLower(o.Label), "vpn не работает") && !strings.Contains(o.Label, "не значит") {
		t.Errorf("404 label misleading: %s", o.Label)
	}
}

func TestTransportErrors(t *testing.T) {
	th := Thresholds{}
	cases := []struct {
		stage model.Stage
		kind  model.ErrorKind
		code  string
	}{
		{model.StageDNS, model.ErrDNS, "dns_error"},
		{model.StageDNS, model.ErrTimeout, "dns_timeout"},
		{model.StageTCP, model.ErrRefused, "tcp_refused"},
		{model.StageTCP, model.ErrTimeout, "tcp_timeout"},
		{model.StageTCP, model.ErrUnreachable, "tcp_unreachable"},
		{model.StageTLS, model.ErrTLSCert, "tls_cert_error"},
		{model.StageTLS, model.ErrTLSHandshake, "tls_handshake_error"},
		{model.StageTLS, model.ErrTimeout, "tls_timeout"},
		{model.StageHTTP, model.ErrTimeout, "http_timeout"},
		{model.StageProxy, model.ErrProxy, "proxy_error"},
		{model.StageDNS, model.ErrBlockedAddr, "blocked_address"},
		{model.StageTCP, model.ErrCancelled, "cancelled"},
	}
	for _, c := range cases {
		r := failRes(c.stage, c.kind)
		o := Probe(&r, model.Endpoint{}, th)
		if o.Code != c.code {
			t.Errorf("%s/%s: want %s got %+v", c.stage, c.kind, c.code, o)
		}
		if c.code == "cancelled" {
			if o.Level != model.LevelNeutral {
				t.Errorf("cancelled must be neutral, not an error: %+v", o)
			}
			continue
		}
		if o.Level != model.LevelError || o.Detail != "tech detail" {
			t.Errorf("%s: level/detail wrong: %+v", c.code, o)
		}
	}
}

func TestTLSOnlyAndSlowThreshold(t *testing.T) {
	r := model.ProbeResult{Kind: model.KindTLS, Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(800)}}
	o := Probe(&r, model.Endpoint{}, Thresholds{SlowMs: 1500})
	if o.Code != "tls_ok" || o.Level != model.LevelOK || !strings.Contains(o.Label, "не проверялась") {
		t.Fatalf("tls ok: %+v", o)
	}
	o = Probe(&r, model.Endpoint{}, Thresholds{SlowMs: 500})
	if o.Code != "tls_slow" || o.Level != model.LevelWarn || !strings.Contains(o.Detail, "порог 500") {
		t.Fatalf("tls slow: %+v", o)
	}
	// Slow also applies to expected HTTP responses, never to failures.
	h := httpsRes(200, nil)
	h.Timings.TLSReadyMs = f(2000)
	o = Probe(&h, model.Endpoint{ExpectedStatuses: []int{200}}, Thresholds{SlowMs: 1500})
	if o.Code != "http_expected_slow" || o.Level != model.LevelWarn {
		t.Fatalf("http slow: %+v", o)
	}
	// Threshold 0 disables the heuristic.
	o = Probe(&h, model.Endpoint{ExpectedStatuses: []int{200}}, Thresholds{})
	if o.Level != model.LevelOK {
		t.Fatalf("threshold 0 must disable slow: %+v", o)
	}
}

func TestSkippedAndBodyError(t *testing.T) {
	r := model.ProbeResult{Skipped: true, Outcome: Skipped("hourly_cap", "Пропущено: потолок проб")}
	if o := Probe(&r, model.Endpoint{}, Thresholds{}); o.Code != "hourly_cap" || o.Level != model.LevelNeutral {
		t.Fatalf("skipped: %+v", o)
	}
	h := httpsRes(200, func(x *model.HTTPResult) { x.BodyError = "превышен тайм-аут" })
	o := Probe(&h, model.Endpoint{ExpectedStatuses: []int{200}}, Thresholds{})
	if o.Level != model.LevelOK || !strings.Contains(o.Detail, "тело ответа") {
		t.Fatalf("body error must be a detail, not a failure: %+v", o)
	}
}

func TestGroupAggregation(t *testing.T) {
	ok := model.ProbeResult{Outcome: model.Outcome{Level: model.LevelOK}, Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(100)}}
	ok2 := ok
	ok2.Timings.TLSReadyMs = f(300)
	warn := model.ProbeResult{Outcome: model.Outcome{Level: model.LevelWarn}, Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(200)}}
	errR := model.ProbeResult{Outcome: model.Outcome{Level: model.LevelError}}
	skip := model.ProbeResult{Skipped: true, Outcome: model.Outcome{Level: model.LevelNeutral}}

	g := Group("g", "G", []model.ProbeResult{ok, ok2, warn})
	if g.Level != model.LevelWarn || g.Label != "2/3 доступны, 1 ответ отклонён/ограничен" {
		t.Fatalf("mixed: %+v", g)
	}
	if g.MedianMs == nil || *g.MedianMs != 200 {
		t.Fatalf("median: %+v", g.MedianMs)
	}
	g = Group("g", "G", []model.ProbeResult{ok, errR, errR})
	if g.Level != model.LevelWarn || !strings.Contains(g.Label, "1/3 доступны") || !strings.Contains(g.Label, "2 ошибки") {
		t.Fatalf("one ok + errors must not be green: %+v", g)
	}
	g = Group("g", "G", []model.ProbeResult{errR, errR})
	if g.Level != model.LevelError || g.Label != "0/2 доступны, 2 ошибки" {
		t.Fatalf("all errors: %+v", g)
	}
	g = Group("g", "G", []model.ProbeResult{ok, ok2})
	if g.Level != model.LevelOK || g.Label != "2/2 доступны" {
		t.Fatalf("all ok: %+v", g)
	}
	g = Group("g", "G", []model.ProbeResult{skip, skip})
	if g.Level != model.LevelNeutral || g.Label != "Не проверено" {
		t.Fatalf("all skipped: %+v", g)
	}
	g = Group("g", "G", []model.ProbeResult{ok, skip})
	if g.Level != model.LevelOK || g.Label != "1/1 доступны, 1 не проверено" {
		t.Fatalf("ok + skipped: %+v", g)
	}
}

func TestSummarizeAndStability(t *testing.T) {
	run := &model.Run{
		Endpoints: []model.Endpoint{{ID: "a", ExpectedStatuses: []int{200}}, {ID: "b", ExpectedStatuses: []int{401}}},
		Results: []model.ProbeResult{
			{EndpointID: "a", Kind: model.KindHTTPS, Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(100)}, HTTP: &model.HTTPResult{Status: 200}, Outcome: model.Outcome{Level: model.LevelOK}},
			{EndpointID: "b", Kind: model.KindHTTPS, Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(300)}, HTTP: &model.HTTPResult{Status: 429}, Outcome: model.Outcome{Level: model.LevelWarn}},
			{EndpointID: "c", Kind: model.KindTLS, Transport: model.Transport{OK: false}, Outcome: model.Outcome{Level: model.LevelError}},
			{EndpointID: "d", Kind: model.KindTLS, Skipped: true, Outcome: Skipped("hourly_cap", "x")},
		},
	}
	Summarize(run)
	c := run.Counts
	if c.Planned != 4 || c.Probed != 3 || c.TLSOK != 2 || c.HTTPSTotal != 2 || c.HTTPMatch != 1 || c.Errors != 1 || c.Skipped != 1 || c.Limited != 2 {
		t.Fatalf("counts: %+v", c)
	}
	if run.MedianTLSReady == nil || *run.MedianTLSReady != 200 {
		t.Fatalf("median: %v", run.MedianTLSReady)
	}

	s := Stability([]model.ProbeResult{
		{Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(120)}},
		{Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(90)}},
		{Transport: model.Transport{OK: false}},
	})
	if s.N != 3 || s.Success != 2 || *s.MinMs != 90 || *s.MaxMs != 120 || *s.SpreadMs != 30 || *s.MedianMs != 105 || !s.SmallSample {
		t.Fatalf("stability: %+v", s)
	}
	if Stability(nil).MinMs != nil {
		t.Fatal("empty series must have null metrics")
	}
}
