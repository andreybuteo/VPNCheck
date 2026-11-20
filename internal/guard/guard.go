// Package guard validates target addresses. It blocks loopback, private,
// link-local, multicast, reserved and cloud-metadata addresses in both IPv4
// and IPv6, and it is applied again at connect time on the exact IP being
// dialed, which closes DNS-rebinding windows.
//
// The only allowed exception is an explicitly user-configured proxy address,
// which is dialed without this guard by the probe engine.
package guard

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"vpncheck/internal/i18n"
)

// BlockedError is returned when an address is not allowed.
type BlockedError struct {
	Addr   string
	Reason string
}

func (e *BlockedError) Error() string {
	return i18n.T("адрес %s заблокирован: %s", e.Addr, e.Reason)
}

// Policy controls what the guard allows.
type Policy struct {
	// AllowLoopback permits 127.0.0.0/8 and ::1. It exists only so that tests can
	// run against local servers. Production code always uses Default(), and the
	// value is never exposed through settings or the API.
	AllowLoopback bool
}

// Default returns the production policy.
func Default() Policy { return Policy{} }

var blockedV4 = []struct {
	prefix string
	reason string
}{
	{"0.0.0.0/8", "«этот» узел"},
	{"10.0.0.0/8", "частная сеть"},
	{"100.64.0.0/10", "shared address space (CGNAT/VPN)"},
	{"169.254.0.0/16", "link-local / metadata"},
	{"172.16.0.0/12", "частная сеть"},
	{"192.0.0.0/24", "IETF protocol assignments"},
	{"192.0.2.0/24", "документационный диапазон"},
	{"192.88.99.0/24", "6to4 relay anycast (устарел)"},
	{"192.168.0.0/16", "частная сеть"},
	{"198.18.0.0/15", "benchmarking"},
	{"198.51.100.0/24", "документационный диапазон"},
	{"203.0.113.0/24", "документационный диапазон"},
	{"224.0.0.0/4", "multicast"},
	{"240.0.0.0/4", "зарезервировано"},
	{"255.255.255.255/32", "broadcast"},
}

var blockedV6 = []struct {
	prefix string
	reason string
}{
	{"::/128", "неопределённый адрес"},
	{"::ffff:0:0/96", "IPv4-mapped"}, // handled by unmapping first, kept as safety net
	{"64:ff9b::/96", "NAT64"},        // checked via embedded IPv4 as well
	{"100::/64", "discard-only"},
	{"2001:db8::/32", "документационный диапазон"},
	{"2002::/16", "6to4"}, // checked via embedded IPv4 as well
	{"fc00::/7", "unique local (частная сеть)"},
	{"fe80::/10", "link-local"},
	{"fec0::/10", "site-local (устарел)"},
	{"ff00::/8", "multicast"},
}

var (
	v4Prefixes []netip.Prefix
	v4Reasons  []string
	v6Prefixes []netip.Prefix
	v6Reasons  []string
)

func init() {
	for _, b := range blockedV4 {
		v4Prefixes = append(v4Prefixes, netip.MustParsePrefix(b.prefix))
		v4Reasons = append(v4Reasons, b.reason)
	}
	for _, b := range blockedV6 {
		v6Prefixes = append(v6Prefixes, netip.MustParsePrefix(b.prefix))
		v6Reasons = append(v6Reasons, b.reason)
	}
}

// Check returns nil if ip may be connected to under the policy.
func (p Policy) Check(ip net.IP) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return &BlockedError{Addr: ip.String(), Reason: i18n.T("некорректный IP")}
	}
	return p.CheckAddr(addr)
}

// CheckAddr is Check for netip.Addr.
func (p Policy) CheckAddr(addr netip.Addr) error {
	orig := addr
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.IsLoopback() {
		if p.AllowLoopback {
			return nil
		}
		return &BlockedError{Addr: orig.String(), Reason: "loopback"}
	}
	if addr.Is4() {
		return check4(orig, addr)
	}
	// Embedded IPv4 inside well-known translation prefixes.
	if nat64 := netip.MustParsePrefix("64:ff9b::/96"); nat64.Contains(addr) {
		b := addr.As16()
		v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if v4.IsLoopback() && !p.AllowLoopback {
			return &BlockedError{Addr: orig.String(), Reason: "NAT64 → loopback"}
		}
		if err := check4(orig, v4); err != nil {
			return &BlockedError{Addr: orig.String(), Reason: "NAT64 → " + err.(*BlockedError).Reason}
		}
		return &BlockedError{Addr: orig.String(), Reason: "NAT64"}
	}
	if sixToFour := netip.MustParsePrefix("2002::/16"); sixToFour.Contains(addr) {
		b := addr.As16()
		v4 := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
		if err := check4(orig, v4); err != nil {
			return &BlockedError{Addr: orig.String(), Reason: "6to4 → " + err.(*BlockedError).Reason}
		}
		return &BlockedError{Addr: orig.String(), Reason: "6to4"}
	}
	for i, pfx := range v6Prefixes {
		if pfx.Contains(addr) {
			return &BlockedError{Addr: orig.String(), Reason: i18n.T(v6Reasons[i])}
		}
	}
	return nil
}

func check4(orig, addr netip.Addr) error {
	for i, pfx := range v4Prefixes {
		if pfx.Contains(addr) {
			return &BlockedError{Addr: orig.String(), Reason: i18n.T(v4Reasons[i])}
		}
	}
	return nil
}

// Control is a net.Dialer.Control function that re-checks the exact address
// about to be connected. It is the last line of defence against DNS rebinding.
func (p Policy) Control(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return &BlockedError{Addr: address, Reason: i18n.T("некорректный адрес")}
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if i := strings.IndexByte(host, '%'); i >= 0 { // zone
		return &BlockedError{Addr: address, Reason: i18n.T("адрес с зоной интерфейса")}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return &BlockedError{Addr: address, Reason: i18n.T("не IP-адрес")}
	}
	return p.CheckAddr(addr)
}

// ValidateHostname checks that host is a syntactically valid public DNS name
// or a permitted IP literal. It rejects credentials, ports, wildcards,
// trailing dots, ".local"/".localhost"/".internal" style names and IP literals
// that the policy blocks.
func (p Policy) ValidateHostname(host string) error {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return errors.New(i18n.T("пустое имя хоста"))
	}
	if strings.ContainsAny(h, "@/:?#\\ \t\r\n") {
		return errors.New(i18n.T("имя хоста содержит недопустимые символы"))
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return p.CheckAddr(addr)
	}
	if len(h) > 253 {
		return errors.New(i18n.T("имя хоста слишком длинное"))
	}
	if strings.HasSuffix(h, ".") {
		return errors.New(i18n.T("имя хоста не должно оканчиваться точкой"))
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return errors.New(i18n.T("нужно полное доменное имя с точкой"))
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return errors.New(i18n.T("некорректная часть доменного имени"))
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New(i18n.T("часть имени не может начинаться или заканчиваться дефисом"))
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New(i18n.T("имя хоста содержит недопустимые символы"))
			}
		}
	}
	switch labels[len(labels)-1] {
	case "local", "localhost", "internal", "lan", "home", "corp", "intranet", "onion", "arpa", "test", "example", "invalid":
		return errors.New(i18n.T("зарезервированная или непубличная доменная зона"))
	}
	return nil
}
