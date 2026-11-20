package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// dialInfo collects what the dialer observed for one probe.
type dialInfo struct {
	start    time.Time
	dnsMs    *float64
	tcpMs    *float64
	proxyMs  *float64
	resolved []string
	peer     string
	family   string
	proven   bool
	stage    model.Stage // stage currently in progress (= failed stage on error)
}

func familyOf(addr net.Addr) string {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp.IP == nil {
		return ""
	}
	if ip4 := tcp.IP.To4(); ip4 != nil {
		return "ipv4"
	}
	return "ipv6"
}

// dial opens a TCP connection to host:port through the configured route.
func (p *Prober) dial(ctx context.Context, host, port string, info *dialInfo) (net.Conn, error) {
	if p.o.Route.Mode == model.RouteProxy {
		return p.dialViaProxy(ctx, host, port, info)
	}
	return p.dialDirect(ctx, host, port, info)
}

// dialDirect resolves locally, filters by the requested family, applies the
// address guard and connects with a Happy-Eyeballs race. TCP time is measured
// from the first connection attempt to the winning connection, never as a sum
// of parallel attempts.
func (p *Prober) dialDirect(ctx context.Context, host, port string, info *dialInfo) (net.Conn, error) {
	p.notify(info, model.StageDNS)
	t0 := time.Now()
	addrs, err := p.o.Resolver.LookupIPAddr(ctx, host)
	info.dnsMs = model.Ms(time.Since(t0))
	if err != nil {
		return nil, err
	}
	var cands []netip.Addr
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if len(info.resolved) < 8 {
			info.resolved = append(info.resolved, ip.String())
		}
		switch p.o.Family {
		case model.FamilyV4:
			if !ip.Is4() {
				continue
			}
		case model.FamilyV6:
			if ip.Is4() {
				continue
			}
		}
		cands = append(cands, ip)
	}
	if len(cands) == 0 {
		if len(addrs) > 0 {
			return nil, &net.DNSError{Err: i18n.T("нет адресов выбранного семейства IP"), Name: host}
		}
		return nil, &net.DNSError{Err: i18n.T("нет адресов"), Name: host, IsNotFound: true}
	}
	var allowed []netip.Addr
	var blocked error
	for _, c := range cands {
		if err := p.o.Policy.CheckAddr(c); err != nil {
			blocked = err
			continue
		}
		allowed = append(allowed, c)
	}
	if len(allowed) == 0 {
		return nil, blocked
	}

	p.notify(info, model.StageTCP)
	tcpCtx, cancel := context.WithTimeout(ctx, p.o.TCPTimeout)
	defer cancel()
	t1 := time.Now()
	conn, err := p.happyEyeballs(tcpCtx, allowed, port)
	info.tcpMs = model.Ms(time.Since(t1))
	if err != nil {
		if tcpCtx.Err() != nil && ctx.Err() == nil {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	info.peer = conn.RemoteAddr().String()
	info.family = familyOf(conn.RemoteAddr())
	info.proven = true
	return conn, nil
}

// happyEyeballs races the first address family against the other one after a
// short fallback delay (RFC 8305 style). Attempts inside one family are
// sequential; the first successful connection wins and the rest are closed.
func (p *Prober) happyEyeballs(ctx context.Context, addrs []netip.Addr, port string) (net.Conn, error) {
	var primary, fallback []netip.Addr
	first := addrs[0].Is4()
	for _, a := range addrs {
		if a.Is4() == first {
			primary = append(primary, a)
		} else {
			fallback = append(fallback, a)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	dialer := &net.Dialer{Control: p.o.Policy.Control, KeepAlive: -1}
	type result struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan result, 2)
	primaryDone := make(chan struct{})

	tryList := func(list []netip.Addr, wait <-chan struct{}, done chan struct{}) {
		if done != nil {
			defer close(done)
		}
		if wait != nil {
			select {
			case <-wait:
			case <-ctx.Done():
				resCh <- result{err: ctx.Err()}
				return
			}
		}
		var lastErr error
		for _, a := range list {
			if ctx.Err() != nil {
				break
			}
			c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
			if err == nil {
				resCh <- result{conn: c}
				return
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = ctx.Err()
			if lastErr == nil {
				lastErr = errors.New(i18n.T("нет адресов для подключения"))
			}
		}
		resCh <- result{err: lastErr}
	}

	n := 1
	go tryList(primary, nil, primaryDone)
	if len(fallback) > 0 {
		n = 2
		wait := make(chan struct{})
		go func() {
			timer := time.NewTimer(p.o.FallbackDelay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-primaryDone:
			case <-ctx.Done():
			}
			close(wait)
		}()
		go tryList(fallback, wait, nil)
	}

	var firstErr error
	for i := 0; i < n; i++ {
		r := <-resCh
		if r.conn != nil {
			cancel()
			remaining := n - i - 1
			if remaining > 0 {
				go func() {
					for j := 0; j < remaining; j++ {
						if rr := <-resCh; rr.conn != nil {
							rr.conn.Close()
						}
					}
				}()
			}
			return r.conn, nil
		}
		if firstErr == nil || errors.Is(firstErr, context.Canceled) || errors.Is(firstErr, context.DeadlineExceeded) {
			firstErr = r.err
		}
	}
	return nil, firstErr
}

// dialViaProxy connects to the user-configured proxy and asks it to open a
// tunnel to host:port. The proxy address is the only address that bypasses
// the guard, because the user typed it deliberately. The target name is sent
// to the proxy as a name (remote DNS) — no local lookup of the target happens,
// so DNS and the target's address family are reported as not measured.
func (p *Prober) dialViaProxy(ctx context.Context, host, port string, info *dialInfo) (net.Conn, error) {
	proxyHost, proxyPort, err := net.SplitHostPort(p.o.Route.ProxyAddr)
	if err != nil {
		return nil, &proxyError{msg: i18n.T("некорректный адрес прокси: ") + sanitizeText(p.o.Route.ProxyAddr, 100)}
	}
	if _, err := strconv.Atoi(proxyPort); err != nil {
		return nil, &proxyError{msg: i18n.T("некорректный порт прокси")}
	}
	p.notify(info, model.StageTCP)
	tcpCtx, cancel := context.WithTimeout(ctx, p.o.TCPTimeout)
	defer cancel()
	t0 := time.Now()
	conn, err := (&net.Dialer{KeepAlive: -1}).DialContext(tcpCtx, "tcp", net.JoinHostPort(proxyHost, proxyPort))
	info.tcpMs = model.Ms(time.Since(t0))
	if err != nil {
		if tcpCtx.Err() != nil && ctx.Err() == nil {
			return nil, &proxyError{msg: i18n.T("тайм-аут подключения к прокси")}
		}
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		kind, text := classifyErr(err)
		return nil, &proxyError{msg: i18n.T("прокси недоступен (") + string(kind) + "): " + text}
	}
	info.peer = conn.RemoteAddr().String()
	info.family = familyOf(conn.RemoteAddr())
	info.proven = false

	p.notify(info, model.StageProxy)
	hsCtx, cancelHS := context.WithTimeout(ctx, p.o.TCPTimeout)
	defer cancelHS()
	t1 := time.Now()
	var tunnel net.Conn
	err = withCancelClose(hsCtx, conn, func() error {
		var e error
		switch p.o.Route.ProxyKind {
		case model.ProxySOCKS5:
			tunnel, e = socks5Connect(conn, host, port)
		case model.ProxyHTTP:
			tunnel, e = httpConnect(conn, host, port, p.o.UserAgent)
		default:
			e = &proxyError{msg: i18n.T("неизвестный тип прокси")}
		}
		return e
	})
	info.proxyMs = model.Ms(time.Since(t1))
	if err != nil {
		conn.Close()
		if hsCtx.Err() != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, &proxyError{msg: i18n.T("тайм-аут ответа прокси")}
		}
		var pe *proxyError
		if errors.As(err, &pe) {
			return nil, err
		}
		_, text := classifyErr(err)
		return nil, &proxyError{msg: i18n.T("ошибка прокси: ") + text}
	}
	return tunnel, nil
}

// withCancelClose runs fn and closes conn if ctx ends first, so that a hung
// proxy handshake cannot outlive the probe deadline or a cancellation.
func withCancelClose(ctx context.Context, conn net.Conn, fn func() error) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	err := fn()
	close(done)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
