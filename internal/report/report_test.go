package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vpncheck/internal/model"
)

func f(v float64) *float64 { return &v }

func sampleRun() *model.Run {
	fin := time.Date(2026, 9, 13, 12, 1, 0, 0, time.UTC)
	return &model.Run{
		ID: "20260913T120000Z-abcd", ProfileName: "VPN — Германия", StartedAt: time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC), FinishedAt: &fin,
		Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "127.0.0.1:10809"},
		IPFamily: model.FamilyAuto, SystemProxy: "127.0.0.1:10809", Status: model.RunCompleted,
		Endpoints: []model.Endpoint{
			{ID: "a", GroupID: "g1", Group: "G1", Label: "=SUM(1)", Host: "a.example.com", Kind: model.KindHTTPS, URL: "https://a.example.com/x"},
			{ID: "c", GroupID: "g1", Group: "G1", Label: "custom", Host: "c.example.com", Kind: model.KindHTTPS, URL: "https://c.example.com/p?token=SECRET", Custom: true},
		},
		Results: []model.ProbeResult{
			{EndpointID: "a", GroupID: "g1", Host: "a.example.com", Kind: model.KindHTTPS, URL: "https://a.example.com/x", Attempt: 1, Route: model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "127.0.0.1:10809"},
				Timings: model.Timings{TLSReadyMs: f(200), TTFBMs: f(300)}, Transport: model.Transport{OK: true, PeerAddr: "127.0.0.1:10809", CertVerified: true},
				HTTP: &model.HTTPResult{Status: 200, Proto: "HTTP/2.0"}, Outcome: model.Outcome{Code: "http_expected", Label: "Контрольный ресурс доступен (200)", Level: model.LevelOK}},
			{EndpointID: "c", GroupID: "g1", Host: "c.example.com", Kind: model.KindHTTPS, URL: "https://c.example.com/p?token=SECRET", Attempt: 1, Route: model.RouteConfig{Mode: model.RouteProxy, ProxyAddr: "127.0.0.1:10809"},
				Transport: model.Transport{OK: false, FailedStage: model.StageTLS, ErrorKind: model.ErrTLSCert, ErrorText: "x509: bad"}, Outcome: model.Outcome{Code: "tls_cert_error", Label: "TLS: сертификат не прошёл проверку", Level: model.LevelError, Detail: "-x509"}},
		},
		ExternalIP:     &model.ExternalIP{Provider: "Cloudflare", Before: "203.0.113.5", After: "203.0.113.5", Country: "DE"},
		Counts:         model.Counts{Planned: 2, Probed: 2, TLSOK: 1, HTTPSTotal: 2, HTTPMatch: 1, Errors: 1},
		MedianTLSReady: f(200),
	}
}

func TestJSONExportRedactsByDefault(t *testing.T) {
	run := sampleRun()
	data, err := ExportJSON(run, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, secret := range []string{"203.0.113.5", "10809", "SECRET"} {
		if strings.Contains(s, secret) {
			t.Errorf("redacted export leaks %q", secret)
		}
	}
	var doc JSONDocument
	if err := json.Unmarshal(data, &doc); err != nil || doc.SchemaVersion != 1 || doc.Run == nil {
		t.Fatalf("bad envelope: %v", err)
	}
	if !strings.Contains(s, `"dnsMs": null`) {
		t.Error("unknown metrics must be null")
	}
	// Original untouched.
	if run.Route.ProxyAddr != "127.0.0.1:10809" || run.ExternalIP.Before != "203.0.113.5" {
		t.Error("Redact must not modify the original run")
	}
	full, _ := ExportJSON(run, Options{IncludeSensitive: true})
	if !strings.Contains(string(full), "203.0.113.5") || !strings.Contains(string(full), "10809") {
		t.Error("sensitive export must include the data")
	}
}

func TestCSVIsExcelFriendlyAndInjectionSafe(t *testing.T) {
	data := ExportCSV(sampleRun(), Options{})
	if !strings.HasPrefix(string(data), "\uFEFF") {
		t.Error("BOM missing")
	}
	lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\r\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows, got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "\uFEFFЗапуск;Профиль;") {
		t.Errorf("header: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"'=SUM(1)"`) {
		t.Errorf("formula not neutralised: %s", lines[1])
	}
	if !strings.Contains(lines[2], `"'-x509"`) {
		t.Errorf("leading minus not neutralised: %s", lines[2])
	}
	if strings.Contains(string(data), "SECRET") || strings.Contains(string(data), "10809") {
		t.Error("csv leaks sensitive data")
	}
	if !strings.Contains(lines[1], ";—;") {
		t.Error("unmeasured values must be rendered as —")
	}
	cancelled := sampleRun()
	cancelled.Status = model.RunCancelled
	if !strings.Contains(string(ExportCSV(cancelled, Options{})), "отменён") {
		t.Error("cancelled runs must be marked")
	}
}

func TestSummaryHidesSecretsAndListsProblems(t *testing.T) {
	s := Summary(sampleRun(), Options{})
	for _, want := range []string{"VPN — Германия", "Проверено узлов: 2 из 2", "TLS подтверждён: 1/2", "HTTP-ответ по профилю: 1/2", "G1", "сертификат не прошёл проверку", "не гарантируется"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
	for _, secret := range []string{"203.0.113.5", "10809"} {
		if strings.Contains(s, secret) {
			t.Errorf("summary leaks %q", secret)
		}
	}
	if !strings.Contains(Summary(sampleRun(), Options{IncludeSensitive: true}), "203.0.113.5") {
		t.Error("sensitive summary must include IP")
	}
}

func TestCompare(t *testing.T) {
	a := sampleRun()
	b := sampleRun()
	b.ID = "b"
	b.Route = model.RouteConfig{Mode: model.RouteSystem}
	b.Results[0].Timings.TLSReadyMs = f(150)
	b.Results[1].Transport = model.Transport{OK: true}
	b.Results[1].Timings.TLSReadyMs = f(90)
	b.Results[1].Outcome = model.Outcome{Code: "http_expected", Level: model.LevelOK}
	b.Endpoints = append(b.Endpoints, model.Endpoint{ID: "new", GroupID: "g2", Group: "G2"})
	b.Results = append(b.Results, model.ProbeResult{EndpointID: "new", Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(10)}})

	c := Compare(a, b)
	if !c.RouteChanged || len(c.Notes) == 0 {
		t.Error("route change must be noted")
	}
	if len(c.Rows) != 2 || len(c.OnlyInB) != 1 || c.OnlyInB[0] != "new" {
		t.Fatalf("rows=%d onlyInB=%v", len(c.Rows), c.OnlyInB)
	}
	rowA := c.Rows[0]
	if rowA.EndpointID != "a" || *rowA.DeltaMs != -50 || *rowA.DeltaPct != -25 || rowA.Changed {
		t.Errorf("row a: %+v", rowA)
	}
	rowC := c.Rows[1]
	if !rowC.Changed || rowC.DeltaMs != nil || rowC.Before.Level != model.LevelError || rowC.After.Level != model.LevelOK {
		t.Errorf("row c: delta must be nil when 'before' was not measured: %+v", rowC)
	}
	// Incomparable when the URL changed.
	b2 := sampleRun()
	b2.Endpoints[0].URL = "https://a.example.com/other"
	c2 := Compare(a, b2)
	if c2.Rows[0].Comparable || c2.Rows[0].DeltaMs != nil {
		t.Errorf("url change must make the row incomparable: %+v", c2.Rows[0])
	}
	// Zero base → no percentage.
	a3, b3 := sampleRun(), sampleRun()
	a3.Results[0].Timings.TLSReadyMs = f(0)
	c3 := Compare(a3, b3)
	if c3.Rows[0].DeltaPct != nil {
		t.Error("percentage must be nil for a zero base")
	}
	// Stability mode uses the median of successful attempts.
	a4 := sampleRun()
	a4.Mode = model.ModeStability
	a4.Results = []model.ProbeResult{
		{EndpointID: "a", Attempt: 1, Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(100)}},
		{EndpointID: "a", Attempt: 2, Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(300)}},
		{EndpointID: "a", Attempt: 3, Transport: model.Transport{OK: true}, Timings: model.Timings{TLSReadyMs: f(200)}},
	}
	c4 := Compare(a4, a4)
	if c4.Rows[0].BeforeMs == nil || *c4.Rows[0].BeforeMs != 200 {
		t.Errorf("stability median expected 200, got %v", c4.Rows[0].BeforeMs)
	}
}

func TestPrivacyAcrossExports(t *testing.T) {
	run := sampleRun()
	run.AltRoute = &model.RouteConfig{Mode: model.RouteProxy, ProxyAddr: "proxy.example:8181"}
	run.Split = &model.SplitCheck{DomesticIP: "192.0.2.11"}
	run.Splits = []*model.SplitCheck{nil, {Group: "cn-direct", ForeignIP: "2001:db8::18"}}
	run.Environment = json.RawMessage(`{"adapters":[{"ipv4":["192.0.2.50"]}],"proxies":{"pac":"https://pac.example/private","notes":["PAC https://pac.example/private"],"env":{"HTTPS_PROXY":"other.example:8000"}},"verdict":{"mode":"proxy","text":"other.example:8000","suggestedRoute":{"proxyAddr":"other.example:8000"}}}`)
	evidence := "proxy.example:8181 reported 192.0.2.11 and 2001:db8::18"
	run.Verdicts = []model.Verdict{{Title: evidence, Evidence: []string{evidence}}}
	run.Results[0].HTTP.BodySnippet = evidence
	run.Results[0].Transport.ErrorText = run.Endpoints[1].URL
	before, _ := json.Marshal(run)
	j, err := ExportJSON(run, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Diagnostic(run, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{j, d, ExportCSV(run, Options{}), []byte(Summary(run, Options{}))} {
		for _, secret := range []string{"proxy.example", "pac.example", "other.example", "192.0.2.11", "192.0.2.50", "2001:db8::18", "SECRET"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("redaction missed %q", secret)
			}
		}
	}
	after, _ := json.Marshal(run)
	if string(after) != string(before) {
		t.Fatal("redaction changed history")
	}
	full, _ := Diagnostic(run, nil, Options{IncludeSensitive: true})
	if !strings.Contains(string(full), evidence) || !strings.Contains(string(full), "pac.example") {
		t.Fatal("detailed report lost data")
	}
}

func TestSummaryCountsEachSkippedProbeOnce(t *testing.T) {
	run := sampleRun()
	run.Counts.Limited, run.Counts.Skipped = 2, 1
	run.Results[0].HTTP.Status = 429
	run.Results[1].Skipped = true
	if !strings.Contains(Summary(run, Options{}), "ограничений/пропусков: 2") {
		t.Fatal("skipped probe counted twice")
	}
}
