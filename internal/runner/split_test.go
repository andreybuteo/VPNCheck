package runner

import (
	"testing"

	"vpncheck/internal/model"
)

func TestParseSplitPage(t *testing.T) {
	ip, vpn, _ := ParseSplitPage([]byte(`<div>..</div><script>{"ip":{"v4":"192.0.2.10","v6":null},"isp":{"asn":[1],"localName":null,"isVpn":false}}</script>`))
	if ip != "192.0.2.10" || vpn == nil || *vpn {
		t.Fatalf("yandex page: %q %v", ip, vpn)
	}
	if ip, _, _ := ParseSplitPage([]byte("198.51.100.7\n")); ip != "198.51.100.7" {
		t.Fatalf("plain: %q", ip)
	}
	if ip, _, _ := ParseSplitPage([]byte(`{"ip": "198.51.100.8"}`)); ip != "198.51.100.8" {
		t.Fatalf("json: %q", ip)
	}
	if ip, _, _ := ParseSplitPage([]byte(`{"code":0,"data":{"addr":"198.51.100.9","country":"中国"}}`)); ip != "198.51.100.9" {
		t.Fatalf("bilibili: %q", ip)
	}
	if ip, _, _ := ParseSplitPage([]byte("{\n  \"ip\": \"198.51.100.10\",\n  \"country\": \"IR\"\n}")); ip != "198.51.100.10" {
		t.Fatalf("ifconfig.ir: %q", ip)
	}
	if ip, _, _ := ParseSplitPage([]byte(`"127.0.0.1"`)); ip != "" {
		t.Fatalf("loopback must be ignored: %q", ip)
	}
	if ip, _, _ := ParseSplitPage([]byte(`<html>captcha</html>`)); ip != "" {
		t.Fatalf("no ip: %q", ip)
	}
}

func TestCountryFromPage(t *testing.T) {
	cases := []struct{ body, ip, country string }{
		{`{"ip":{"v4":"192.0.2.10","v6":null},"clientRegion":{"name":"Москва","ip":"Москва","passport":null,"id":213}}`, "192.0.2.10", "RU"},
		{`{"ip":{"v4":"192.0.2.11","v6":null},"clientRegion":{"name":"Москва","ip":"Хельсинки","id":10493}}`, "192.0.2.11", "FI"},
		{`{"ip":{"v4":"192.0.2.12","v6":null},"clientRegion":{"name":"Свердловская область","id":11162}}`, "192.0.2.12", "RU"},
		{`{"ip":{"v4":"192.0.2.13","v6":null},"clientRegion":{"name":"Неизвестный город","ip":"Неизвестный город"}}`, "192.0.2.13", ""},
		{`{"code":0,"data":{"addr":"198.51.100.9","country":"中国","province":"广东"}}`, "198.51.100.9", "CN"},
		{`{"code":0,"data":{"addr":"198.51.100.9","country":"中国","province":"香港"}}`, "198.51.100.9", "HK"},
		{`{"code":0,"data":{"addr":"198.51.100.9","country":"芬兰","province":"新地区"}}`, "198.51.100.9", "FI"},
		{"{\n  \"ip\": \"198.51.100.10\",\n  \"country\": \"IR\"\n}", "198.51.100.10", "IR"},
		{`{"ip": {"v6":"2001:0db8:0:0::1","v4":null}, "clientRegion": {"ip":"Минская область"}}`, "2001:db8::1", ""},
		{`{"ip":"192.0.2.4","country":"\u4e2d\u56fd"}`, "192.0.2.4", "CN"},
		{`no address here`, "", ""},
	}
	for _, c := range cases {
		ip, _, country := ParseSplitPage([]byte(c.body))
		if ip != c.ip || country != c.country {
			t.Errorf("%s: got %q %q, want %q %q", c.body, ip, country, c.ip, c.country)
		}
	}
}

func TestClassifySplit(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		s    model.SplitCheck
		want string
	}{
		{model.SplitCheck{DomesticIP: "192.0.2.10", ForeignIP: "203.0.113.7", ForeignCountry: "FI", DomesticVPN: &no}, "split_ok"},
		{model.SplitCheck{DomesticIP: "203.0.113.7", ForeignIP: "203.0.113.7", ForeignCountry: "FI"}, "all_vpn"},
		{model.SplitCheck{DomesticIP: "192.0.2.10", ForeignIP: "192.0.2.10", ForeignCountry: "RU"}, "all_direct"},
		{model.SplitCheck{DomesticIP: "192.0.2.10", ForeignIP: "192.0.2.10"}, "same_exit"},
		{model.SplitCheck{DomesticIP: "192.0.2.10", ForeignIP: "203.0.113.7", ForeignCountry: "RU"}, "foreign_in_home"},
		{model.SplitCheck{DomesticIP: "192.0.2.11", ForeignIP: "203.0.113.7", ForeignCountry: "DE", DomesticVPN: &yes}, "domestic_vpn"},
		{model.SplitCheck{ForeignIP: "203.0.113.7", ForeignCountry: "DE"}, "unknown"},
		{model.SplitCheck{DomesticIP: "192.0.2.10", DomesticCountry: "RU", ForeignIP: "203.0.113.7", ForeignCountry: "FI", DomesticVPN: &no}, "split_ok"},
		{model.SplitCheck{DomesticIP: "198.51.100.9", DomesticCountry: "NL", ForeignIP: "203.0.113.7", ForeignCountry: "FI", DomesticVPN: &no}, "domestic_foreign"},
		{model.SplitCheck{DomesticIP: "192.0.2.10", ForeignIP: "2001:db8::10", DomesticCountry: "RU", ForeignCountry: "FI"}, "unknown"},
		{model.SplitCheck{DomesticIP: "192.0.2.10", ForeignIP: "203.0.113.7", ForeignCountry: "FI"}, "unknown"},
		// Other home countries: China and Iran.
		{model.SplitCheck{Home: "CN", DomesticIP: "192.0.2.20", DomesticCountry: "CN", ForeignIP: "203.0.113.7", ForeignCountry: "JP"}, "split_ok"},
		{model.SplitCheck{Home: "CN", DomesticIP: "192.0.2.20", DomesticCountry: "RU", ForeignIP: "203.0.113.7", ForeignCountry: "JP"}, "domestic_foreign"},
		{model.SplitCheck{Home: "IR", DomesticIP: "192.0.2.30", ForeignIP: "192.0.2.30", ForeignCountry: "IR"}, "all_direct"},
		{model.SplitCheck{Home: "IR", DomesticIP: "192.0.2.30", ForeignIP: "192.0.2.30", ForeignCountry: "DE"}, "all_vpn"},
		{model.SplitCheck{Home: "IR", DomesticIP: "192.0.2.30", DomesticCountry: "IR", ForeignIP: "203.0.113.7", ForeignCountry: "RU"}, "split_ok"},
	}
	for _, c := range cases {
		s := c.s
		ClassifySplit(&s)
		if s.Code != c.want {
			t.Errorf("%+v: got %s, want %s", c.s, s.Code, c.want)
		}
	}
}

func TestSplitCheckInRun(t *testing.T) {
	eps := append(testEndpoints(), model.Endpoint{ID: "ru-y", GroupID: SplitGroup, Group: "RU", Label: "y", Host: "ru.example.com", Kind: model.KindTLS, Enabled: true})
	h := newHarness(t, eps)
	*h.ips = []string{"203.0.113.10", "203.0.113.10"}
	// The option for the external IP is off: selecting the group turns it on.
	sum, err := h.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"t1-web", "ru-y"}})
	if err != nil {
		t.Fatal(err)
	}
	h.r.Wait()
	run, _ := h.st.LoadRun(sum.ID)
	s := run.SplitFor(SplitGroup)
	if s == nil || s.DomesticIP != "192.0.2.10" || s.ForeignIP != "203.0.113.10" || s.ForeignCountry != "DE" || s.DomesticCountry != "RU" || s.Code != "split_ok" {
		t.Fatalf("split: %+v", s)
	}
	var found bool
	for _, v := range run.Verdicts {
		if v.GroupID == SplitGroup {
			found = v.Code == "split_ok" && v.Level == model.LevelOK
		}
	}
	if !found {
		t.Fatalf("verdict: %+v", run.Verdicts)
	}
	// Without the group nothing is asked from the Russian page.
	h2 := newHarness(t, eps)
	sum2, _ := h2.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"t1-web"}})
	h2.r.Wait()
	run2, _ := h2.st.LoadRun(sum2.ID)
	if len(run2.Splits) != 0 || run2.Split != nil {
		t.Fatal("split check must not run without its group")
	}
}
