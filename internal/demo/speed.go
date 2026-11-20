package demo

import (
	"context"
	"math"
	"time"

	"vpncheck/internal/model"
	"vpncheck/internal/speed"
)

// SpeedMeter fabricates a speed test for QA of the interface. No network.
type SpeedMeter struct {
	proxy bool
}

// NewSpeedMeter builds the fake meter for a route.
func NewSpeedMeter(route model.RouteConfig) speed.Meter {
	return &SpeedMeter{proxy: route.Mode == model.RouteProxy}
}

func (m *SpeedMeter) Close() {}

// ExitIP returns documentation-range addresses: one per route, so the demo IP
// strip shows how alternating exits look.
func (m *SpeedMeter) ExitIP(ctx context.Context) (string, string, error) {
	if m.proxy {
		return "198.51.100.24", "NL", nil
	}
	return "203.0.113.77", "DE", nil
}

func (m *SpeedMeter) Latency(ctx context.Context, srv speed.Server) (speed.Latency, error) {
	select {
	case <-time.After(1200 * time.Millisecond):
	case <-ctx.Done():
		return speed.Latency{}, ctx.Err()
	}
	l := speed.Latency{MedianMs: 38, JitterMs: 4.2, Samples: 10, Colo: "FRA"}
	if m.proxy {
		l.MedianMs, l.Colo = 61, "AMS"
	}
	return l, nil
}

func (m *SpeedMeter) fake(ctx context.Context, target float64, live speed.Live) (speed.Throughput, error) {
	const phase = 4 * time.Second
	start := time.Now()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var bytes int64
	for {
		select {
		case <-ctx.Done():
			return speed.Throughput{Bytes: bytes, Seconds: time.Since(start).Seconds()}, ctx.Err()
		case <-tick.C:
			el := time.Since(start)
			ramp := el.Seconds() / 1.5
			if ramp > 1 {
				ramp = 1
			}
			cur := target * ramp * (0.92 + 0.08*math.Sin(el.Seconds()*5) - 0.25*dip(el))
			bytes += int64(cur * 1e6 / 8 * 0.25)
			if live != nil {
				live(cur, bytes, el)
			}
			if el >= phase {
				return speed.Throughput{Mbps: target, Bytes: bytes, Seconds: el.Seconds()}, nil
			}
		}
	}
}

// dip makes one short drop in the middle of a demo phase.
func dip(el time.Duration) float64 {
	if s := el.Seconds(); s > 2.2 && s < 2.8 {
		return 1
	}
	return 0
}

func (m *SpeedMeter) Download(ctx context.Context, _ speed.Server, live speed.Live) (speed.Throughput, error) {
	return m.fake(ctx, 87.4, live)
}

func (m *SpeedMeter) Upload(ctx context.Context, _ speed.Server, live speed.Live) (speed.Throughput, error) {
	return m.fake(ctx, 41.9, live)
}
