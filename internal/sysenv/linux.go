//go:build linux

package sysenv

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vpncheck/internal/i18n"
)

// All data comes from /proc, /sys and /etc without root rights and without
// running external programs.

func readText(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func osVersion() string {
	name := parseOSRelease(readText("/etc/os-release"))
	if name == "" {
		name = "Linux"
	}
	if k := strings.TrimSpace(readText("/proc/sys/kernel/osrelease")); k != "" {
		name += " · kernel " + k
	}
	return name
}

func adapters() ([]Adapter, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	routes := parseProcRoute(readText("/proc/net/route"))
	dns := parseResolvConf(readText("/etc/resolv.conf"))
	var out []Adapter
	for _, in := range ifs {
		if in.Flags&net.FlagLoopback != 0 {
			continue
		}
		sys := filepath.Join("/sys/class/net", in.Name)
		arphrd, _ := strconv.Atoi(strings.TrimSpace(readText(filepath.Join(sys, "type"))))
		devtype := ""
		for _, line := range strings.Split(readText(filepath.Join(sys, "uevent")), "\n") {
			if v, ok := strings.CutPrefix(line, "DEVTYPE="); ok {
				devtype = strings.TrimSpace(v)
			}
		}
		_, tunErr := os.Stat(filepath.Join(sys, "tun_flags"))
		a := Adapter{Index: in.Index, Name: in.Name, Description: linuxDescription(in.Name, devtype, arphrd),
			Up: in.Flags&net.FlagUp != 0, IfType: uint32(arphrd), IPv4: []string{}, IPv6: []string{}, DNS: []string{}, Gateway: []string{}}
		a.TunLike = IsLinuxTunnel(in.Name, arphrd, devtype, tunErr == nil)
		if addrs, err := in.Addrs(); err == nil {
			for _, ad := range addrs {
				ipn, ok := ad.(*net.IPNet)
				if !ok {
					continue
				}
				if ipn.IP.To4() != nil {
					a.IPv4 = append(a.IPv4, ipn.IP.String())
				} else if !ipn.IP.IsLinkLocalUnicast() {
					a.IPv6 = append(a.IPv6, ipn.IP.String())
				}
			}
		}
		for _, r := range routes {
			if r.Iface == in.Name && r.Dest.Equal(net.IPv4zero) && r.Mask.Equal(net.IPv4zero) {
				if !r.Gateway.Equal(net.IPv4zero) {
					a.Gateway = append(a.Gateway, r.Gateway.String())
				}
				a.Metric = r.Metric
			}
		}
		out = append(out, a)
	}
	// resolv.conf is global on Linux: show it on the adapters that carry a default route.
	for i := range out {
		if len(out[i].Gateway) > 0 || out[i].Metric > 0 {
			out[i].DNS = dns
		}
	}
	return out, nil
}

func linuxDescription(name, devtype string, arphrd int) string {
	switch {
	case devtype != "":
		return devtype
	case arphrd == arphrdNone:
		return "tun"
	case arphrd == arphrdPPP:
		return "ppp"
	case arphrd == 1:
		return "ethernet"
	}
	return name
}

// defaultRoute asks the kernel which interface a packet to the internet would
// leave through. Connecting a UDP socket sends nothing but runs the full route
// lookup, including policy rules (wg-quick, sing-box and Clash TUN use their
// own routing tables, which /proc/net/route does not show).
func defaultRoute(ads []Adapter) Route {
	rt := Route{}
	var local net.IP
	if c, err := net.Dial("udp4", "192.0.2.1:53"); err == nil {
		// 192.0.2.0/24 is a documentation range: the lookup follows the default
		// route, and the address is never contacted (UDP connect sends nothing).
		// 198.18.0.0/15 is avoided on purpose: TUN clients use it for fake IPs.
		local = c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
	}
	for _, a := range ads {
		for _, ip := range a.IPv4 {
			if local != nil && local.String() == ip {
				rt.Known, rt.IfIndex, rt.IfName, rt.IfDesc, rt.ViaTunnel = true, a.Index, a.Name, a.Description, a.TunLike
				if len(a.Gateway) > 0 {
					rt.NextHop = a.Gateway[0]
				}
				return rt
			}
		}
	}
	// Fallback: the main table's default route with the lowest metric.
	best := -1
	var bestMetric uint32
	for i, a := range ads {
		if len(a.Gateway) > 0 && a.Up && (best < 0 || a.Metric < bestMetric) {
			best, bestMetric = i, a.Metric
		}
	}
	if best >= 0 {
		a := ads[best]
		rt.Known, rt.IfIndex, rt.IfName, rt.IfDesc, rt.ViaTunnel, rt.NextHop = true, a.Index, a.Name, a.Description, a.TunLike, a.Gateway[0]
		return rt
	}
	rt.Note = i18n.T("маршрут по умолчанию не найден")
	return rt
}

func tcpListeners() ([]Listener, error) {
	v4 := readText("/proc/net/tcp")
	v6 := readText("/proc/net/tcp6")
	if v4 == "" && v6 == "" {
		return nil, errors.New(i18n.T("нет доступа к /proc/net/tcp"))
	}
	socks := append(parseProcTCP(v4, false), parseProcTCP(v6, true)...)
	owners := socketOwners()
	seen := map[string]bool{}
	var out []Listener
	for _, s := range socks {
		key := s.Addr + ":" + strconv.Itoa(s.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Listener{Addr: s.Addr, Port: s.Port, PID: owners[s.Inode]})
	}
	return out, nil
}

// socketOwners maps socket inodes to PIDs. Without root only this user's
// processes are visible; sockets of system services keep PID 0.
func socketOwners() map[string]int {
	out := map[string]int{}
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", d.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", d.Name(), "fd", fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				out[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = pid
			}
		}
	}
	return out
}

func processes() (map[int]string, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		name := strings.TrimSpace(readText(filepath.Join("/proc", d.Name(), "comm")))
		// comm is cut to 15 characters; the executable name from cmdline is complete.
		if cmd := readText(filepath.Join("/proc", d.Name(), "cmdline")); cmd != "" {
			if exe := filepath.Base(strings.SplitN(cmd, "\x00", 2)[0]); exe != "" && exe != "." && strings.HasPrefix(exe, name) {
				name = exe
			}
		}
		if name != "" {
			out[pid] = name
		}
	}
	return out, nil
}
