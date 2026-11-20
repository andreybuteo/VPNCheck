package probe

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpncheck/internal/guard"
	"vpncheck/internal/model"
)

// staticResolver maps names to loopback for tests. It is the only place where
// loopback is allowed, together with guard.Policy{AllowLoopback: true}.
type staticResolver struct {
	m     map[string][]net.IPAddr
	err   error
	block bool // block until ctx is done (simulates a DNS timeout)
	calls atomic.Int32
}

func (r *staticResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	r.calls.Add(1)
	if r.block {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	}
	if r.err != nil {
		return nil, r.err
	}
	if a, ok := r.m[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func loopbackResolver(names ...string) *staticResolver {
	m := map[string][]net.IPAddr{}
	for _, n := range names {
		m[n] = []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}
	}
	return &staticResolver{m: m}
}

// failResolver fails the test when used: proves no local DNS happens in proxy mode.
type failResolver struct{ t *testing.T }

func (r failResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.t.Errorf("local DNS lookup of %q must not happen in proxy mode", host)
	return nil, errors.New("forbidden")
}

// tlsServer is an httptest TLS server with a connection counter.
type tlsServer struct {
	*httptest.Server
	conns atomic.Int32
	reqs  atomic.Int32
	pool  *x509.CertPool
	port  string
}

func newTLSServer(t *testing.T, h http.HandlerFunc) *tlsServer {
	t.Helper()
	s := &tlsServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.reqs.Add(1)
		h(w, r)
	}))
	s.Server.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.conns.Add(1)
		}
	}
	s.Server.EnableHTTP2 = true
	s.Server.StartTLS()
	s.pool = x509.NewCertPool()
	s.pool.AddCert(s.Server.Certificate())
	_, s.port, _ = net.SplitHostPort(s.Listener.Addr().String())
	t.Cleanup(s.Close)
	return s
}

func testOptions(s *tlsServer, res Resolver) Options {
	return Options{
		Policy:        guard.Policy{AllowLoopback: true},
		Resolver:      res,
		RootCAs:       s.pool,
		Timeout:       3 * time.Second,
		TCPTimeout:    2 * time.Second,
		TLSTimeout:    2 * time.Second,
		FallbackDelay: 50 * time.Millisecond,
	}
}

func httpsEndpoint(s *tlsServer, path string) model.Endpoint {
	return model.Endpoint{ID: "t-https", GroupID: "g", Host: "example.com", Kind: model.KindHTTPS,
		URL: "https://example.com:" + s.port + path}
}

// ---- test proxies ----

type proxyOpts struct {
	authRequired bool
	reject       bool
	delay        time.Duration
	// resolve maps target host names to loopback (remote DNS done by the proxy).
	resolve func(host string) string
}

// startConnectProxy starts a minimal HTTP CONNECT proxy.
func startConnectProxy(t *testing.T, o proxyOpts) (addr string, tunnels *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tunnels = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				if o.delay > 0 {
					time.Sleep(o.delay)
				}
				if o.authRequired {
					io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n")
					return
				}
				if o.reject {
					io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					return
				}
				host, port, _ := net.SplitHostPort(req.Host)
				target := net.JoinHostPort(o.resolve(host), port)
				up, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				defer up.Close()
				tunnels.Add(1)
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				pipe(c, up)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), tunnels
}

// startSocks5Proxy starts a minimal SOCKS5 proxy (no auth, CONNECT, domain names).
func startSocks5Proxy(t *testing.T, o proxyOpts) (addr string, tunnels *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tunnels = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
					return
				}
				methods := make([]byte, hdr[1])
				io.ReadFull(c, methods)
				if o.delay > 0 {
					time.Sleep(o.delay)
				}
				if o.authRequired {
					c.Write([]byte{5, 2})
					return
				}
				c.Write([]byte{5, 0})
				var req [4]byte
				if _, err := io.ReadFull(c, req[:]); err != nil || req[1] != 1 || req[3] != 3 {
					c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				var l [1]byte
				io.ReadFull(c, l[:])
				name := make([]byte, l[0])
				io.ReadFull(c, name)
				var pb [2]byte
				io.ReadFull(c, pb[:])
				port := binary.BigEndian.Uint16(pb[:])
				if o.reject {
					c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				up, err := net.DialTimeout("tcp", net.JoinHostPort(o.resolve(string(name)), strconv.Itoa(int(port))), time.Second)
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				tunnels.Add(1)
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				pipe(c, up)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), tunnels
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(a, b); a.Close() }()
	go func() { defer wg.Done(); io.Copy(b, a); b.Close() }()
	wg.Wait()
}

func loopbackAll(string) string { return "127.0.0.1" }

func ms(v *float64) float64 {
	if v == nil {
		return -1
	}
	return *v
}
