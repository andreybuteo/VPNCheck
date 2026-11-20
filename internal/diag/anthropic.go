package diag

import (
	"strings"
	"vpncheck/internal/model"
)

// AnthropicNetworkOK requires both control endpoints on the primary route.
// It makes no assertion about account access or model inference.
func AnthropicNetworkOK(run *model.Run) bool {
	latest := map[string]model.ProbeResult{}
	for _, r := range run.Results {
		if r.GroupID != "anthropic" || r.Route != run.Route {
			continue
		}
		if old, ok := latest[r.EndpointID]; !ok || r.Attempt >= old.Attempt {
			latest[r.EndpointID] = r
		}
	}
	web, api := latest["anthropic-web"], latest["anthropic-api"]
	good := func(r model.ProbeResult) bool {
		return !r.Skipped && r.Transport.OK && r.Transport.CertVerified && (r.Outcome.Level == model.LevelOK || r.Outcome.Code == "tls_ok_slow" || r.Outcome.Code == "http_expected_slow")
	}
	if !good(web) || !good(api) || api.HTTP == nil || api.HTTP.GeoBlocked || api.HTTP.Captcha {
		return false
	}
	return api.HTTP.Status == 200 || (api.HTTP.Status == 401 && strings.Contains(api.HTTP.BodySnippet, "authentication_error"))
}
