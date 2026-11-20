//go:build windows

package sysenv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"vpncheck/internal/i18n"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetAdaptersAddrs    = iphlpapi.NewProc("GetAdaptersAddresses")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetBestRoute        = iphlpapi.NewProc("GetBestRoute")
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetVersion          = kernel32.NewProc("GetVersion")
)

func osVersion() string {
	v, _, _ := procGetVersion.Call()
	major := byte(v)
	minor := byte(v >> 8)
	build := uint16(v >> 16)
	return fmt.Sprintf("Windows %d.%d build %d", major, minor, build)
}

// ---- adapters via GetAdaptersAddresses (manual IP_ADAPTER_ADDRESSES layout, x64) ----

const (
	gaaFlagSkipAnycast    = 0x0002
	gaaFlagSkipMulticast  = 0x0004
	gaaFlagIncludeGateway = 0x0080
	afUnspec              = 0
	afInet                = 2
	afInet6               = 23
)

func u32At(p unsafe.Pointer, off uintptr) uint32 { return *(*uint32)(unsafe.Add(p, off)) }
func u16At(p unsafe.Pointer, off uintptr) uint16 { return *(*uint16)(unsafe.Add(p, off)) }
func ptrAt(p unsafe.Pointer, off uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Add(p, off))
}

func wstr(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	var out []uint16
	for i := uintptr(0); i < 4096; i += 2 {
		c := u16At(p, i)
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return syscall.UTF16ToString(out)
}

// sockaddrIP parses a SOCKET_ADDRESS {lpSockaddr *, iSockaddrLength int32} at p.
func sockaddrIP(p unsafe.Pointer) string {
	sa := ptrAt(p, 0)
	if sa == nil {
		return ""
	}
	switch u16At(sa, 0) {
	case afInet:
		b := (*[4]byte)(unsafe.Add(sa, 4))
		return net.IPv4(b[0], b[1], b[2], b[3]).String()
	case afInet6:
		b := (*[16]byte)(unsafe.Add(sa, 8))
		return net.IP(b[:]).String()
	}
	return ""
}

// addrList walks a chain of {Length u32, Flags/Reserved u32, Next ptr @8, Address @16}.
func addrList(first unsafe.Pointer) []string {
	out := []string{}
	for p := first; p != nil && len(out) < 16; p = ptrAt(p, 8) {
		if ip := sockaddrIP(unsafe.Add(p, 16)); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

func adapters() ([]Adapter, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, errors.New(i18n.T("поддерживается только 64-битная Windows"))
	}
	size := uint32(16 * 1024)
	var buf []byte
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		r, _, _ := procGetAdaptersAddrs.Call(afUnspec, gaaFlagSkipAnycast|gaaFlagSkipMulticast|gaaFlagIncludeGateway, 0,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		if r == 0 {
			break
		}
		if r != 111 { // ERROR_BUFFER_OVERFLOW
			return nil, i18n.Errorf("GetAdaptersAddresses: код %d", r)
		}
	}
	var out []Adapter
	for p := unsafe.Pointer(&buf[0]); p != nil; p = ptrAt(p, 8) {
		a := Adapter{
			Index:       int(u32At(p, 4)),
			Description: wstr(ptrAt(p, 64)),
			Name:        wstr(ptrAt(p, 72)),
			IfType:      u32At(p, 100),
			Up:          u32At(p, 104) == 1,
			Metric:      u32At(p, 216),
			IPv4:        []string{}, IPv6: []string{},
		}
		for u := ptrAt(p, 24); u != nil; u = ptrAt(u, 8) {
			ip := sockaddrIP(unsafe.Add(u, 16))
			switch {
			case ip == "":
			case net.ParseIP(ip).To4() != nil:
				a.IPv4 = append(a.IPv4, ip)
			default:
				a.IPv6 = append(a.IPv6, ip)
			}
		}
		a.DNS = addrList(ptrAt(p, 48))
		a.Gateway = addrList(ptrAt(p, 208))
		a.TunLike = IsTunLike(a.Description, a.IfType)
		out = append(out, a)
		if len(out) > 64 {
			break
		}
	}
	return out, nil
}

// ---- default route via GetBestRoute (no packet is sent) ----

func defaultRoute(ads []Adapter) Route {
	dest := binary.LittleEndian.Uint32([]byte{1, 1, 1, 1})
	var row [14]uint32
	r, _, _ := procGetBestRoute.Call(uintptr(dest), 0, uintptr(unsafe.Pointer(&row[0])))
	if r != 0 {
		return Route{Note: i18n.T("GetBestRoute: код %d", r)}
	}
	nh := make([]byte, 4)
	binary.LittleEndian.PutUint32(nh, row[3])
	rt := Route{Known: true, IfIndex: int(row[4]), NextHop: net.IPv4(nh[0], nh[1], nh[2], nh[3]).String()}
	for _, a := range ads {
		if a.Index == rt.IfIndex {
			rt.IfName, rt.IfDesc, rt.ViaTunnel = a.Name, a.Description, a.TunLike
		}
	}
	if rt.IfName == "" {
		if ifc, err := net.InterfaceByIndex(rt.IfIndex); err == nil {
			rt.IfName = ifc.Name
		}
	}
	return rt
}

// ---- listening TCP ports with owning PIDs ----

func tcpListeners() ([]Listener, error) {
	const tcpTableOwnerPidListener = 3
	size := uint32(0)
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidListener, 0)
	if size == 0 {
		return nil, errors.New(i18n.T("GetExtendedTcpTable: нулевой размер"))
	}
	buf := make([]byte, size+1024)
	r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidListener, 0)
	if r != 0 {
		return nil, i18n.Errorf("GetExtendedTcpTable: код %d", r)
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	var out []Listener
	for i := uint32(0); i < n && int(4+(i+1)*24) <= len(buf); i++ {
		row := buf[4+i*24 : 4+(i+1)*24]
		addr := net.IPv4(row[4], row[5], row[6], row[7]).String()
		port := int(binary.BigEndian.Uint16(row[8:10]))
		pid := int(binary.LittleEndian.Uint32(row[20:24]))
		out = append(out, Listener{Addr: addr, Port: port, PID: pid})
	}
	return out, nil
}

// ---- processes via Toolhelp snapshot ----

func processes() (map[int]string, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	out := map[int]string{}
	if err := syscall.Process32First(snap, &pe); err != nil {
		return nil, err
	}
	for {
		out[int(pe.ProcessID)] = syscall.UTF16ToString(pe.ExeFile[:])
		if err := syscall.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return out, nil
}
