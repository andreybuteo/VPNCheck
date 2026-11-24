package sysenv

// Parsers for the Linux /proc and /sys files. They have no build tag so the
// tests run on every system; linux.go feeds them the real files.

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// procRoute is one line of /proc/net/route.
type procRoute struct {
	Iface   string
	Dest    net.IP
	Gateway net.IP
	Mask    net.IP
	Metric  uint32
	Up      bool
}

// hexIPv4 decodes the little-endian hex address used by /proc/net/route and /proc/net/tcp.
func hexIPv4(s string) net.IP {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return nil
	}
	return net.IPv4(b[3], b[2], b[1], b[0])
}

// hexIPv6 decodes /proc/net/tcp6 addresses: four little-endian 32-bit words.
func hexIPv6(s string) net.IP {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil
	}
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(ip[i*4:], binary.LittleEndian.Uint32(b[i*4:]))
	}
	return ip
}

// parseProcRoute reads /proc/net/route (the main routing table, IPv4).
func parseProcRoute(text string) []procRoute {
	var out []procRoute
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[0] == "Iface" {
			continue
		}
		flags, _ := strconv.ParseUint(f[3], 16, 32)
		metric, _ := strconv.ParseUint(f[6], 10, 32)
		out = append(out, procRoute{Iface: f[0], Dest: hexIPv4(f[1]), Gateway: hexIPv4(f[2]), Mask: hexIPv4(f[7]), Metric: uint32(metric), Up: flags&1 != 0})
	}
	return out
}

// procListener is a listening TCP socket from /proc/net/tcp or tcp6.
type procListener struct {
	Addr  string
	Port  int
	Inode string
}

// parseProcTCP returns the sockets in state LISTEN (0A).
func parseProcTCP(text string, v6 bool) []procListener {
	var out []procListener
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		host, port, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(port, 16, 16)
		if err != nil {
			continue
		}
		var ip net.IP
		if v6 {
			ip = hexIPv6(host)
		} else {
			ip = hexIPv4(host)
		}
		if ip == nil {
			continue
		}
		addr := ip.String()
		if v4 := ip.To4(); v4 != nil && v6 && !ip.Equal(net.IPv4zero) {
			addr = v4.String() // ::ffff:127.0.0.1
		}
		out = append(out, procListener{Addr: addr, Port: int(p), Inode: f[9]})
	}
	return out
}

// parseOSRelease returns PRETTY_NAME (or NAME VERSION) from /etc/os-release.
func parseOSRelease(text string) string {
	vals := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			vals[k] = strings.Trim(v, `"'`)
		}
	}
	if s := vals["PRETTY_NAME"]; s != "" {
		return s
	}
	return strings.TrimSpace(vals["NAME"] + " " + vals["VERSION"])
}

// parseResolvConf returns the nameserver addresses.
func parseResolvConf(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil {
			out = append(out, f[1])
		}
	}
	return out
}

// Linux ARPHRD_* interface types (/sys/class/net/<if>/type).
const (
	arphrdPPP  = 512
	arphrdNone = 65534 // tun devices, WireGuard
)

// linuxTunnelPrefixes are interface names that VPN clients commonly create.
var linuxTunnelPrefixes = []string{"tun", "tap", "wg", "awg", "utun", "ppp", "tailscale", "nekoray", "nekobox", "sing", "singbox", "clash", "mihomo", "meta", "hiddify", "throne", "outline", "amn", "proton", "nordlynx", "mullvad", "ipsec", "vti", "zt"}

// IsLinuxTunnel classifies a Linux interface from its name, ARPHRD type,
// kernel device type (uevent DEVTYPE) and whether it has tun_flags.
func IsLinuxTunnel(name string, arphrd int, devtype string, tunFlags bool) bool {
	if tunFlags || arphrd == arphrdNone || arphrd == arphrdPPP {
		return true
	}
	switch devtype {
	case "wireguard", "amneziawg", "ppp", "vti", "ipip", "gre", "ip6tnl":
		return true
	}
	n := strings.ToLower(name)
	for _, p := range linuxTunnelPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}
