package probe

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AllowedRequestHeaders are the only per-endpoint request headers the engine
// will send. Credentials, cookies and host-affecting headers are never allowed.
var AllowedRequestHeaders = []string{"Accept", "Accept-Language", "Anthropic-Version"}

func allowedRequestHeader(name string) bool {
	for _, a := range AllowedRequestHeaders {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}

// parseRetryAfter handles both forms of Retry-After: delay-seconds and HTTP-date.
func parseRetryAfter(v string, now time.Time) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return time.Time{}, false
		}
		return now.Add(time.Duration(secs) * time.Second), true
	}
	if t, err := http.ParseTime(v); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// rateLimitReset derives a reset time from Retry-After and the rate-limit reset
// headers whose semantics are documented:
//   - Retry-After: delay-seconds | HTTP-date (RFC 9110)
//   - X-RateLimit-Reset: Unix epoch seconds (GitHub REST API)
//   - RateLimit-Reset: delta seconds (IETF draft-ietf-httpapi-ratelimit-headers)
//   - X-RateLimit-Reset-Requests / -Tokens: Go-style duration such as "6m0s" (OpenAI)
//
// Returns the earliest usable value; ok=false when nothing parseable was present.
func rateLimitReset(h http.Header, now time.Time) (time.Time, bool) {
	var best time.Time
	set := func(t time.Time) {
		if t.After(now) && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	if t, ok := parseRetryAfter(h.Get("Retry-After"), now); ok {
		set(t)
	}
	if v := strings.TrimSpace(h.Get("X-RateLimit-Reset")); v != "" {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil && epoch > 1_000_000_000 && epoch < 100_000_000_000 {
			set(time.Unix(epoch, 0))
		}
	}
	if v := strings.TrimSpace(h.Get("RateLimit-Reset")); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs >= 0 {
			set(now.Add(time.Duration(secs) * time.Second))
		}
	}
	for _, name := range []string{"X-RateLimit-Reset-Requests", "X-RateLimit-Reset-Tokens"} {
		v := strings.TrimSpace(h.Get(name))
		if v == "" {
			continue
		}
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			set(now.Add(d))
		}
	}
	if best.IsZero() {
		return time.Time{}, false
	}
	return best, true
}

// detectCaptcha is a conservative heuristic for bot-challenge pages. It only
// reports true for blocking statuses combined with well-known markers.
func detectCaptcha(status int, h http.Header, body []byte) bool {
	if strings.EqualFold(h.Get("cf-mitigated"), "challenge") {
		return true
	}
	if strings.EqualFold(h.Get("x-amzn-waf-action"), "challenge") {
		return true
	}
	if status != 403 && status != 429 && status != 503 && status != 401 {
		return false
	}
	lower := strings.ToLower(string(body))
	for _, m := range []string{"cf-chl", "challenge-platform", "captcha", "just a moment", "verify you are human", "_cf_chl_opt"} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// geoMarkers are phrases that services use when they refuse a region/country.
var geoMarkers = []string{
	"unsupported_country_region_territory", "country, region, or territory not supported",
	"not available in your country", "not available in your region", "isn't available in your country",
	"is not available in your location", "unavailable in your region", "unavailable in your country",
	"not supported in your region", "unsupported region", "unsupported location", "unsupported_country",
	"access to this service is not available from your location", "unavailable for legal reasons",
	"недоступен в вашем регионе", "недоступен в вашей стране",
}

// detectGeoBlock recognises "not available in your country" answers.
func detectGeoBlock(status int, body []byte) (bool, string) {
	if status == 451 {
		return true, "HTTP 451 Unavailable For Legal Reasons"
	}
	if status != 403 && status != 401 && status != 400 && status != 404 && status != 503 {
		return false, ""
	}
	lower := strings.ToLower(string(body))
	for _, m := range geoMarkers {
		if strings.Contains(lower, m) {
			return true, m
		}
	}
	return false, ""
}

// bodySnippet returns a short text excerpt of a body for diagnosis: tags
// stripped, whitespace collapsed, control characters removed.
func bodySnippet(body []byte, max int) string {
	s := string(body)
	if i := strings.Index(strings.ToLower(s), "<body"); i >= 0 {
		s = s[i:]
	}
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			b.WriteByte(' ')
		case !inTag:
			b.WriteRune(r)
		}
	}
	return sanitizeText(b.String(), max)
}

// safeLocation returns a display-safe Location header value. Query strings are
// stripped so that tokens embedded in redirects never reach logs or exports.
func safeLocation(v string) string {
	v = sanitizeText(v, 512)
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i] + "…"
	}
	return v
}
