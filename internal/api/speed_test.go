package api

import (
	"context"
	"testing"
	"time"

	"vpncheck/internal/speed"
)

// slowMeter is a network-free meter whose download lasts long enough to test
// overlapping requests.
type slowMeter struct{}

func (slowMeter) Close() {}
func (slowMeter) ExitIP(context.Context) (string, string, error) {
	return "203.0.113.9", "DE", nil
}
func (slowMeter) Latency(context.Context, speed.Server) (speed.Latency, error) {
	return speed.Latency{MedianMs: 20, Samples: 10, Colo: "FRA"}, nil
}
func (slowMeter) Download(ctx context.Context, _ speed.Server, _ speed.Live) (speed.Throughput, error) {
	select {
	case <-time.After(400 * time.Millisecond):
	case <-ctx.Done():
		return speed.Throughput{}, ctx.Err()
	}
	return speed.Throughput{Mbps: 50, Bytes: 5e7, Seconds: 8}, nil
}
func (slowMeter) Upload(context.Context, speed.Server, speed.Live) (speed.Throughput, error) {
	return speed.Throughput{Mbps: 20, Bytes: 2e7, Seconds: 8}, nil
}

func TestSpeedEndpoints(t *testing.T) {
	cl, _ := newClient(t)
	var view struct {
		Enabled bool           `json:"enabled"`
		Servers []speed.Server `json:"servers"`
		History []speed.Result `json:"history"`
		Current *speed.Progress
	}
	if code := cl.do("GET", "/api/speed", nil, &view); code != 200 || !view.Enabled || len(view.Servers) < 2 {
		t.Fatalf("speed view: %d %+v", code, view)
	}
	var errBody map[string]any
	if code := cl.do("POST", "/api/speed", map[string]any{"serverId": "nope", "route": map[string]any{"mode": "system"}}, &errBody); code != 400 {
		t.Fatalf("unknown server: %d", code)
	}
	if code := cl.do("POST", "/api/speed", map[string]any{"serverId": "cloudflare", "route": map[string]any{"mode": "system"}}, nil); code != 202 {
		t.Fatalf("start: %d", code)
	}
	if code := cl.do("POST", "/api/run", map[string]any{"mode": "fast", "route": map[string]any{"mode": "system"}, "ipFamily": "auto", "endpointIds": []string{"openai-api"}, "slowThresholdMs": 1500}, &errBody); code != 409 || errBody["error"] != "speed_active" {
		t.Fatalf("probe run during speed test: %d %v", code, errBody)
	}
	time.Sleep(900 * time.Millisecond)
	if code := cl.do("POST", "/api/speed", map[string]any{"serverId": "cloudflare", "route": map[string]any{"mode": "system"}}, &errBody); code != 429 || errBody["error"] != "speed_cooldown" {
		t.Fatalf("second start within the pause: %d %v", code, errBody)
	}
	cl.do("GET", "/api/speed", nil, &view)
	if len(view.History) != 1 || view.History[0].Status != "completed" || view.History[0].Colo != "FRA" {
		t.Fatalf("history: %+v", view.History)
	}
	if view.History[0].ExitIP != "203.0.113.9" {
		t.Fatalf("exit IP not recorded: %+v", view.History[0])
	}
	var st struct {
		IPLog struct {
			Enabled bool `json:"enabled"`
			Entries []struct {
				IP   string `json:"ip"`
				Kind string `json:"kind"`
			} `json:"entries"`
		} `json:"ipLog"`
	}
	cl.do("GET", "/api/state", nil, &st)
	if !st.IPLog.Enabled || len(st.IPLog.Entries) == 0 || st.IPLog.Entries[len(st.IPLog.Entries)-1].IP != "203.0.113.9" || st.IPLog.Entries[len(st.IPLog.Entries)-1].Kind != "speed" {
		t.Fatalf("ip log: %+v", st.IPLog)
	}
	if code := cl.do("DELETE", "/api/speed/"+view.History[0].ID, nil, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
}
