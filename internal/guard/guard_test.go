package guard

import (
	"errors"
	"net"
	"testing"
)

func TestBlockedAddresses(t *testing.T) {
	p := Default()
	blocked := []string{
		"127.0.0.1", "127.8.8.8", "::1",
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "169.254.1.1", // metadata / link-local
		"100.64.0.1", "100.127.255.255", // CGNAT
		"0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"192.0.2.10", "198.51.100.1", "203.0.113.7", "198.18.0.1", "192.0.0.170",
		"::", "fe80::1", "fc00::1", "fd12::1", "ff02::1", "fec0::1", "2001:db8::1", "100::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::808:808", // NAT64 (any)
		"2002:7f00:1::", "2002:a00:1::", "2002:808:808::", // 6to4 (any)
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test ip %q", s)
		}
		if err := p.Check(ip); err == nil {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "140.82.121.4", "2606:4700::6810:84e5", "2a00:1450:4001:80b::200e", "172.32.0.1", "11.0.0.1"}
	for _, s := range allowed {
		if err := p.Check(net.ParseIP(s)); err != nil {
			t.Errorf("%s should be allowed: %v", s, err)
		}
	}
}

func TestLoopbackOnlyWithTestPolicy(t *testing.T) {
	test := Policy{AllowLoopback: true}
	for _, s := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if err := test.Check(net.ParseIP(s)); err != nil {
			t.Errorf("test policy should allow %s: %v", s, err)
		}
	}
	// Loopback exception must not open anything else.
	for _, s := range []string{"10.0.0.1", "169.254.169.254", "fe80::1", "64:ff9b::7f00:1"} {
		if err := test.Check(net.ParseIP(s)); err == nil {
			t.Errorf("test policy must still block %s", s)
		}
	}
}

func TestControlBlocksExactDialAddress(t *testing.T) {
	p := Default()
	cases := map[string]bool{
		"127.0.0.1:443":                true,
		"[::1]:443":                    true,
		"[fe80::1%eth0]:443":           true,
		"[::ffff:169.254.169.254]:443": true,
		"example.com:443":              true, // Control must only ever see IPs
		"1.1.1.1:443":                  false,
		"[2606:4700::6810:84e5]:443":   false,
	}
	for addr, wantBlocked := range cases {
		err := p.Control("tcp", addr, nil)
		var be *BlockedError
		gotBlocked := errors.As(err, &be)
		if gotBlocked != wantBlocked {
			t.Errorf("Control(%s): blocked=%v want %v (err=%v)", addr, gotBlocked, wantBlocked, err)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	p := Default()
	good := []string{"api.openai.com", "Claude.AI", "registry-1.docker.io", "1.1.1.1", "xn--80ak6aa92e.com"}
	for _, h := range good {
		if err := p.ValidateHostname(h); err != nil {
			t.Errorf("%q should be valid: %v", h, err)
		}
	}
	bad := []string{
		"", "localhost", "example.com.", "user@host.com", "host.com:443", "*.googlevideo.com",
		"127.0.0.1", "10.0.0.5", "::1", "printer.local", "nas.lan", "foo.internal", "onlyone",
		"-bad.example.com", "bad-.example.com", "a b.com", "host.example", "x.test", "metadata.internal",
	}
	for _, h := range bad {
		if err := p.ValidateHostname(h); err == nil {
			t.Errorf("%q should be rejected", h)
		}
	}
}
