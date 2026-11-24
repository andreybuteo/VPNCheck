package sysenv

import "testing"

func TestParseProcRoute(t *testing.T) {
	text := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"enp3s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"enp3s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	r := parseProcRoute(text)
	if len(r) != 2 || r[0].Iface != "enp3s0" || r[0].Gateway.String() != "192.168.1.1" || !r[0].Dest.IsUnspecified() || r[0].Metric != 100 || !r[0].Up {
		t.Fatalf("%+v", r)
	}
	if r[1].Dest.String() != "192.168.1.0" || r[1].Mask.String() != "255.255.255.0" {
		t.Fatalf("%+v", r[1])
	}
}

func TestParseProcTCP(t *testing.T) {
	v4 := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:2A38 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41234 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:2A39 0100007F:A000 01 00000000:00000000 00:00000000 00000000  1000        0 41235 1 0000000000000000 100 0 0 10 0\n"
	l := parseProcTCP(v4, false)
	if len(l) != 1 || l[0].Addr != "127.0.0.1" || l[0].Port != 10808 || l[0].Inode != "41234" {
		t.Fatalf("v4: %+v", l)
	}
	v6 := "  sl  local_address                         remote_address                        st\n" +
		"   0: 00000000000000000000000001000000:2A39 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 51234 1\n" +
		"   1: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 51235 1\n"
	l = parseProcTCP(v6, true)
	if len(l) != 2 || l[0].Addr != "::1" || l[0].Port != 10809 || l[1].Addr != "127.0.0.1" || l[1].Port != 8080 {
		t.Fatalf("v6: %+v", l)
	}
}

func TestParseOSReleaseAndResolv(t *testing.T) {
	if s := parseOSRelease("NAME=\"Ubuntu\"\nVERSION=\"24.04 LTS\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"); s != "Ubuntu 24.04 LTS" {
		t.Fatal(s)
	}
	if s := parseOSRelease("NAME=Arch\nVERSION=rolling\n"); s != "Arch rolling" {
		t.Fatal(s)
	}
	ns := parseResolvConf("# comment\nnameserver 127.0.0.53\noptions edns0\nnameserver ::1\nnameserver bogus\n")
	if len(ns) != 2 || ns[0] != "127.0.0.53" || ns[1] != "::1" {
		t.Fatal(ns)
	}
}

func TestIsLinuxTunnel(t *testing.T) {
	cases := []struct {
		name    string
		arphrd  int
		devtype string
		tun     bool
		want    bool
	}{
		{"enp3s0", 1, "", false, false},
		{"wlp2s0", 1, "wlan", false, false},
		{"wg0", 65534, "wireguard", false, true},
		{"tun0", 65534, "", true, true},
		{"nekoray-tun", 65534, "", true, true},
		{"ppp0", 512, "", false, true},
		{"docker0", 1, "bridge", false, false},
		{"awg0", 1, "", false, true},
	}
	for _, c := range cases {
		if got := IsLinuxTunnel(c.name, c.arphrd, c.devtype, c.tun); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}
