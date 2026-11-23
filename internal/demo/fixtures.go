//i18nkeys:skip — demo answers of local sites, data rather than interface text.

package demo

// Yandex Internetometer answers: through the VPN (proxy route) and direct.
const (
	yandexViaVPN = `<html>{"ip":{"v4":"198.51.100.24","v6":null},"isp":{"asn":[64500],"isVpn":true},"clientRegion":{"name":"Москва","ip":"Амстердам","passport":null,"id":10466}}</html>`
	yandexDirect = `<html>{"ip":{"v4":"192.0.2.10","v6":null},"isp":{"asn":[64501],"isVpn":false},"clientRegion":{"name":"Москва","ip":"Москва","passport":null,"id":213}}</html>`
)
