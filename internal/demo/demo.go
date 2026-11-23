// Package demo provides a fake probe engine for QA of the interface. It never
// touches the network: results are deterministic per hostname. The mode is
// enabled only with the --demo flag, uses a separate data directory and is
// clearly marked in the UI. A normal launch never shows fabricated results.
package demo

import (
	"context"
	"hash/fnv"
	"strings"
	"time"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
	"vpncheck/internal/probe"
	"vpncheck/internal/runner"
)

// Prober is the fake engine.
type Prober struct {
	o probe.Options
}

// New builds a demo prober.
func New(o probe.Options) runner.Prober { return &Prober{o: o} }

func ms(v float64) *float64 { return &v }

func (p *Prober) Probe(ctx context.Context, ep model.Endpoint) model.ProbeResult {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ep.Host))
	seed := h.Sum32()
	res := model.ProbeResult{EndpointID: ep.ID, GroupID: ep.GroupID, Host: ep.Host, URL: ep.URL, Kind: ep.Kind, Attempt: 1, StartedAt: time.Now().UTC(), Route: p.o.Route, IPFamily: p.o.Family}
	delay := time.Duration(150+seed%900) * time.Millisecond
	stages := []model.Stage{model.StageDNS, model.StageTCP, model.StageTLS, model.StageHTTP}
	for i, st := range stages {
		if p.o.OnStage != nil {
			p.o.OnStage(st)
		}
		select {
		case <-time.After(delay / time.Duration(len(stages))):
		case <-ctx.Done():
			res.Transport = model.Transport{OK: false, FailedStage: st, ErrorKind: model.ErrCancelled, ErrorText: i18n.T("операция отменена")}
			res.Timings.TotalMs = ms(float64(i) * 10)
			return res
		}
	}
	base := float64(20 + seed%120)
	res.Timings = model.Timings{DNSMs: ms(base * 0.3), TCPMs: ms(base), TLSMs: ms(base * 1.4), TLSReadyMs: ms(base * 2.7), TotalMs: ms(base * 3)}
	proxy := p.o.Route.Mode == model.RouteProxy
	if proxy {
		res.Timings.DNSMs = nil
		res.Timings.ProxyMs = ms(base * 0.5)
		res.Transport.PeerAddr = p.o.Route.ProxyAddr
		res.Transport.PeerFamily = "ipv4"
	} else {
		res.Transport.PeerAddr = "203.0.113.10:443"
		res.Transport.PeerFamily = "ipv4"
		res.Transport.FamilyProven = true
		res.Transport.ResolvedAddrs = []string{"203.0.113.10"}
	}
	switch seed % 9 {
	case 0:
		res.Transport.OK = false
		res.Transport.FailedStage = model.StageTCP
		res.Transport.ErrorKind = model.ErrTimeout
		res.Transport.ErrorText = i18n.T("dial tcp: i/o timeout (демо)")
		res.Timings.TLSMs, res.Timings.TLSReadyMs = nil, nil
		return res
	case 1:
		res.Transport.OK = false
		res.Transport.FailedStage = model.StageTLS
		res.Transport.ErrorKind = model.ErrTLSCert
		res.Transport.ErrorText = i18n.T("x509: certificate signed by unknown authority (демо)")
		res.Timings.TLSReadyMs = nil
		return res
	}
	res.Transport.OK = true
	res.Transport.FailedStage = model.StageDone
	res.Transport.CertVerified = true
	res.Transport.TLSVersion = "TLS 1.3"
	res.Transport.ALPN = "h2"
	res.Transport.CertSubject = ep.Host
	res.Transport.CertIssuer = "Demo CA"
	res.Transport.CertNotAfter = time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if ep.Kind == model.KindHTTPS {
		status := 200
		if len(ep.ExpectedStatuses) > 0 {
			status = ep.ExpectedStatuses[0]
		}
		switch seed % 7 {
		case 2:
			status = 429
		case 3:
			status = 302
		}
		if ep.Host == "api.openai.com" && !proxy {
			// Demo of a geo-block on the direct route: exit country not served.
			status = 403
		}
		res.HTTP = &model.HTTPResult{Status: status, Proto: "HTTP/2.0", BytesRead: int64(300 + seed%2000), Server: "demo"}
		if status == 403 {
			res.HTTP.GeoBlocked = true
			res.HTTP.GeoSignature = "unsupported_country_region_territory"
			res.HTTP.BodySnippet = i18n.T(`{"error":{"code":"unsupported_country_region_territory","message":"Country, region, or territory not supported"}} (демо)`)
		}
		if status == 302 {
			res.HTTP.Location = "https://" + ep.Host + "/other…"
		}
		if status == 429 {
			res.HTTP.RetryAfter = "120"
			res.HTTP.RateLimitReset = time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339)
		}
		res.Timings.TTFBMs = ms(base * 3.4)
		res.Timings.TotalMs = ms(base * 3.6)
	}
	return res
}

// FetchSmall fakes the external-IP provider.
func (p *Prober) FetchSmall(ctx context.Context, url string, limit int64) (int, []byte, error) {
	select {
	case <-time.After(200 * time.Millisecond):
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
	if strings.Contains(url, "bilibili.com") || strings.Contains(url, "ifconfig.ir") {
		// The other home countries go through the VPN in the demo: red cards.
		if p.o.Route.Mode == model.RouteProxy {
			return 200, []byte(`{"code":0,"data":{"addr":"198.51.100.24","country":"荷兰","province":"北荷兰省"}}`), nil
		}
		return 200, []byte(`{"code":0,"data":{"addr":"203.0.113.77","country":"德国","province":"黑森州"}}`), nil
	}
	if strings.Contains(url, "yandex.ru") {
		// Split routing: direct on the system route, everything via the VPN through the proxy.
		if p.o.Route.Mode == model.RouteProxy {
			return 200, []byte(yandexViaVPN), nil
		}
		return 200, []byte(yandexDirect), nil
	}
	if p.o.Route.Mode == model.RouteProxy {
		return 200, []byte("fl=demo\nip=198.51.100.24\nloc=NL\n"), nil
	}
	return 200, []byte("fl=demo\nip=203.0.113.77\nloc=DE\n"), nil
}
