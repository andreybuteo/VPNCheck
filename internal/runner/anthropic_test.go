package runner

import (
	"testing"
	"time"
	"vpncheck/internal/diag"
	"vpncheck/internal/model"
	"vpncheck/internal/report"
)

func successfulAnthropic(at time.Time) *model.Run {
	route := model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "127.0.0.1:10808"}
	run := &model.Run{ID: "baseline", StartedAt: at, Status: model.RunCompleted, Route: route, Endpoints: []model.Endpoint{{GroupID: "anthropic"}}, ExternalIP: &model.ExternalIP{Before: "203.0.113.10", After: "203.0.113.10", Country: "FI"}}
	for _, id := range []string{"anthropic-web", "anthropic-api"} {
		result := model.ProbeResult{EndpointID: id, GroupID: "anthropic", Route: route, Attempt: 1, Transport: model.Transport{OK: true, CertVerified: true}, Outcome: model.Outcome{Level: model.LevelOK}}
		if id == "anthropic-api" {
			result.HTTP = &model.HTTPResult{Status: 401, BodySnippet: `{"error":{"type":"authentication_error"}}`}
		}
		run.Results = append(run.Results, result)
	}
	return run
}

func TestAnthropicComparisonAndRedaction(t *testing.T) {
	h := newHarness(t, testEndpoints())
	at := time.Now().Add(-time.Hour)
	old := successfulAnthropic(at)
	if !diag.AnthropicNetworkOK(old) {
		t.Fatal("expected complete network success")
	}
	if err := h.st.SaveRun(old); err != nil {
		t.Fatal(err)
	}
	current := successfulAnthropic(time.Now())
	current.ID = "current"
	for _, tc := range []struct {
		before, after, want string
		changed             bool
	}{
		{"203.0.113.10", "203.0.113.10", "same", false},
		{"203.0.113.20", "203.0.113.20", "different", false},
		{"", "203.0.113.20", "current_ip_unknown", false},
		{"203.0.113.10", "203.0.113.20", "changed_during_run", true},
	} {
		current.ExternalIP = &model.ExternalIP{Before: tc.before, After: tc.after, Changed: tc.changed}
		h.r.compareAnthropicIP(current)
		if x := current.ExternalIP; x.Comparison != tc.want || x.PreviousIP != "203.0.113.10" {
			t.Fatalf("comparison: %+v", x)
		}
	}
	redacted := report.Redact(current, report.Options{})
	if redacted.ExternalIP.PreviousIP == current.ExternalIP.PreviousIP {
		t.Fatal("previous IP leaked")
	}
	if current.ExternalIP.PreviousIP != "203.0.113.10" {
		t.Fatal("redaction mutated history")
	}
	old.ExternalIP = nil
	if err := h.st.SaveRun(old); err != nil {
		t.Fatal(err)
	}
	current.ExternalIP = &model.ExternalIP{Before: "203.0.113.20", After: "203.0.113.20"}
	h.r.compareAnthropicIP(current)
	if current.ExternalIP.Comparison != "previous_ip_unknown" {
		t.Fatal("legacy IP must not be guessed")
	}
	old.Results[1].HTTP.Status = 403
	if diag.AnthropicNetworkOK(old) {
		t.Fatal("403 must not count as success")
	}
	old.Results[1].HTTP.Status = 401
	old.Results[1].Skipped = true
	if diag.AnthropicNetworkOK(old) {
		t.Fatal("skipped probe must not count as success")
	}
}

func TestAnthropicIPAutomaticWithoutFlag(t *testing.T) {
	eps := testEndpoints()
	eps[0].GroupID = "anthropic"
	h := newHarness(t, eps)
	*h.ips = []string{"203.0.113.10", "203.0.113.10"}
	sum, err := h.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"t1-web"}})
	if err != nil {
		t.Fatal(err)
	}
	h.r.Wait()
	run, err := h.st.LoadRun(sum.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.ExternalIP == nil || run.ExternalIP.After != "203.0.113.10" || len(*h.ips) != 0 {
		t.Fatal("Anthropic must collect IP automatically")
	}
}
