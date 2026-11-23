// Package model defines the data types shared by the registry, probe engine,
// classifier, store, reports and API. It has no dependencies on other packages.
package model

import (
	"encoding/json"
	"time"
)

// SchemaVersion is the version of the persisted/exported JSON structures.
const SchemaVersion = 1

// ProbeKind selects the type of check performed for an endpoint.
type ProbeKind string

const (
	// KindTLS performs DNS → TCP 443 → TLS handshake with certificate
	// verification and closes the connection. No HTTP request is sent.
	KindTLS ProbeKind = "tls"
	// KindHTTPS performs a single GET to a small public resource and measures
	// DNS/TCP/TLS/TTFB on that same request.
	KindHTTPS ProbeKind = "https"
)

// Endpoint is one control point of the registry.
type Endpoint struct {
	ID               string    `json:"id"`
	GroupID          string    `json:"groupId"`
	Group            string    `json:"group"`
	Label            string    `json:"label"`
	Host             string    `json:"host"`
	URL              string    `json:"url,omitempty"`
	Kind             ProbeKind `json:"kind"`
	ExpectedStatuses []int     `json:"expectedStatuses,omitempty"`
	// Headers are extra request headers for https probes (allow-listed names only,
	// e.g. Accept or Anthropic-Version). Never credentials.
	Headers        map[string]string `json:"headers,omitempty"`
	Enabled        bool              `json:"enabled"`
	DisabledReason string            `json:"disabledReason,omitempty"`
	Source         string            `json:"source,omitempty"`
	VerifiedAt     string            `json:"verifiedAt,omitempty"`
	Note           string            `json:"note,omitempty"`
	Custom         bool              `json:"custom,omitempty"`
}

// RouteMode is how the application reaches the network.
type RouteMode string

const (
	// RouteSystem uses the current Windows routing (TUN or plain), no application-level proxy.
	RouteSystem RouteMode = "system"
	// RouteProxy uses an explicitly configured HTTP CONNECT or SOCKS5 proxy.
	RouteProxy RouteMode = "proxy"
)

// ProxyKind is the proxy protocol.
type ProxyKind string

const (
	ProxyHTTP   ProxyKind = "http"
	ProxySOCKS5 ProxyKind = "socks5"
)

// RouteConfig describes the selected route. It never contains credentials.
type RouteConfig struct {
	Mode      RouteMode `json:"mode"`
	ProxyKind ProxyKind `json:"proxyKind,omitempty"`
	ProxyAddr string    `json:"proxyAddr,omitempty"` // host:port
}

// IPFamily is the requested address family for a run.
type IPFamily string

const (
	FamilyAuto IPFamily = "auto"
	FamilyV4   IPFamily = "ipv4"
	FamilyV6   IPFamily = "ipv6"
)

// RunMode is the probing strategy.
type RunMode string

const (
	ModeFast      RunMode = "fast"
	ModeStability RunMode = "stability"
	// ModeDiag probes selected endpoints through two routes (the chosen one
	// and the alternative) to tell "blocked here" from "blocked there".
	ModeDiag RunMode = "diag"
)

// Settings is the persisted user configuration.
type Settings struct {
	SchemaVersion   int         `json:"schemaVersion"`
	ProfileName     string      `json:"profileName"`
	Theme           string      `json:"theme"` // "dark" | "light"
	Route           RouteConfig `json:"route"`
	IPFamily        IPFamily    `json:"ipFamily"`
	Mode            RunMode     `json:"mode"`
	SlowThresholdMs int         `json:"slowThresholdMs"` // applied to tlsReadyMs
	ShowExternalIP  bool        `json:"showExternalIp"`
	// RunCooldownSec is the pause between run starts, in seconds (0 = default).
	RunCooldownSec int `json:"runCooldownSec"`
	// SpeedServer is the speed-test target id; SpeedAcknowledged records that
	// the user has seen the traffic warning once.
	SpeedServer       string `json:"speedServer"`
	SpeedAcknowledged bool   `json:"speedAcknowledged"`
	// IPLogOff turns off the exit-IP log: no IP request at each run and speed test.
	IPLogOff bool `json:"ipLogOff"`
	// Language is the interface language code; "" = follow the browser/Windows.
	Language string `json:"language"`
	// SelectedEndpoints lists endpoint IDs chosen for the next run; empty = all enabled.
	SelectedEndpoints []string `json:"selectedEndpoints"`
	// StabilityEndpoints lists up to 5 endpoint IDs for stability mode.
	StabilityEndpoints []string `json:"stabilityEndpoints"`
}

// DefaultSettings returns the initial configuration.
func DefaultSettings() Settings {
	return Settings{
		SchemaVersion:   SchemaVersion,
		ProfileName:     "",
		Theme:           "dark",
		Route:           RouteConfig{Mode: RouteSystem},
		IPFamily:        FamilyAuto,
		Mode:            ModeFast,
		SlowThresholdMs: 1500,
		RunCooldownSec:  60,
		SpeedServer:     "cloudflare",
	}
}

// Timings holds per-phase durations in milliseconds. nil means "not measured".
type Timings struct {
	DNSMs      *float64 `json:"dnsMs"`
	TCPMs      *float64 `json:"tcpMs"`
	ProxyMs    *float64 `json:"proxyMs"`    // CONNECT / SOCKS handshake, proxy mode only
	TLSMs      *float64 `json:"tlsMs"`      // handshake with the target host
	TLSReadyMs *float64 `json:"tlsReadyMs"` // probe start → certificate verified
	TTFBMs     *float64 `json:"ttfbMs"`     // request start → first response byte (https only)
	TotalMs    *float64 `json:"totalMs"`    // whole probe
}

// Stage names the phase in which a probe ended.
type Stage string

const (
	StageNone  Stage = ""
	StageDNS   Stage = "dns"
	StageTCP   Stage = "tcp"
	StageProxy Stage = "proxy"
	StageTLS   Stage = "tls"
	StageHTTP  Stage = "http"
	StageDone  Stage = "done"
)

// ErrorKind is a coarse machine-readable error class.
type ErrorKind string

const (
	ErrNone         ErrorKind = ""
	ErrDNS          ErrorKind = "dns"
	ErrTimeout      ErrorKind = "timeout"
	ErrRefused      ErrorKind = "refused"
	ErrReset        ErrorKind = "reset"
	ErrUnreachable  ErrorKind = "unreachable"
	ErrTLSCert      ErrorKind = "tls_certificate"
	ErrTLSHandshake ErrorKind = "tls_handshake"
	ErrProxy        ErrorKind = "proxy"
	ErrHTTPProtocol ErrorKind = "http_protocol"
	ErrBlockedAddr  ErrorKind = "blocked_address"
	ErrCancelled    ErrorKind = "cancelled"
	ErrLimited      ErrorKind = "limited"
	ErrOther        ErrorKind = "other"
)

// Transport is the connection-level result, kept separate from the HTTP result.
type Transport struct {
	OK          bool      `json:"ok"`
	FailedStage Stage     `json:"failedStage,omitempty"`
	ErrorKind   ErrorKind `json:"errorKind,omitempty"`
	ErrorText   string    `json:"errorText,omitempty"`
	// PeerAddr is the ip:port actually connected to; in proxy mode it is the proxy.
	PeerAddr string `json:"peerAddr,omitempty"`
	// PeerFamily is "ipv4"/"ipv6" of PeerAddr. FamilyProven is false behind a proxy.
	PeerFamily   string `json:"peerFamily,omitempty"`
	FamilyProven bool   `json:"familyProven"`
	// ResolvedAddrs are the addresses returned by local DNS (empty behind proxy).
	ResolvedAddrs []string `json:"resolvedAddrs,omitempty"`
	TLSVersion    string   `json:"tlsVersion,omitempty"`
	ALPN          string   `json:"alpn,omitempty"`
	CertVerified  bool     `json:"certVerified"`
	CertSubject   string   `json:"certSubject,omitempty"`
	CertIssuer    string   `json:"certIssuer,omitempty"`
	CertNotAfter  string   `json:"certNotAfter,omitempty"`
}

// HTTPResult is the response-level result of an https probe.
type HTTPResult struct {
	Status     int    `json:"status"`
	Proto      string `json:"proto"`
	Location   string `json:"location,omitempty"`
	Server     string `json:"server,omitempty"`
	BytesRead  int64  `json:"bytesRead"`
	BodyLimit  bool   `json:"bodyLimited"`
	BodyError  string `json:"bodyError,omitempty"` // headers arrived but the body read failed (e.g. timeout)
	Captcha    bool   `json:"captcha"`
	RetryAfter string `json:"retryAfter,omitempty"`
	// RateLimitReset is an ISO time derived from Retry-After / reset headers, if any.
	RateLimitReset string `json:"rateLimitReset,omitempty"`
	ContentType    string `json:"contentType,omitempty"`
	// BodySnippet is a short sanitised excerpt of a non-2xx body (for diagnosis).
	BodySnippet string `json:"bodySnippet,omitempty"`
	// GeoBlocked is set when the body/headers carry a known "not available in
	// your country/region" signature; GeoSignature names the matched marker.
	GeoBlocked   bool   `json:"geoBlocked"`
	GeoSignature string `json:"geoSignature,omitempty"`
}

// Verdict is a diagnostic conclusion for a service group.
type Verdict struct {
	GroupID     string   `json:"groupId"`
	Group       string   `json:"group"`
	Code        string   `json:"code"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Evidence    []string `json:"evidence"`
	Advice      string   `json:"advice"`
	Confidence  string   `json:"confidence"` // high | medium | low
	Level       Level    `json:"level"`
}

// Level is the visual severity of an outcome.
type Level string

const (
	LevelOK      Level = "ok"
	LevelWarn    Level = "warn"
	LevelError   Level = "error"
	LevelNeutral Level = "neutral"
)

// Outcome is the single human-readable verdict for a probe.
type Outcome struct {
	Code   string `json:"code"`
	Label  string `json:"label"`
	Level  Level  `json:"level"`
	Detail string `json:"detail,omitempty"`
}

// ProbeResult is the result of one probe of one endpoint.
type ProbeResult struct {
	EndpointID     string      `json:"endpointId"`
	GroupID        string      `json:"groupId"`
	Host           string      `json:"host"`
	URL            string      `json:"url,omitempty"`
	Kind           ProbeKind   `json:"kind"`
	Attempt        int         `json:"attempt"`
	StartedAt      time.Time   `json:"startedAt"`
	Route          RouteConfig `json:"route"`
	IPFamily       IPFamily    `json:"ipFamily"`
	Timings        Timings     `json:"timings"`
	Transport      Transport   `json:"transport"`
	HTTP           *HTTPResult `json:"http"`
	Outcome        Outcome     `json:"outcome"`
	Skipped        bool        `json:"skipped"`
	SkipReason     string      `json:"skipReason,omitempty"`
	ProfileVersion int         `json:"profileVersion"`
}

// RunStatus is the completion state of a run.
type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunCompleted RunStatus = "completed"
	RunCancelled RunStatus = "cancelled"
	RunPartial   RunStatus = "partial"
	RunFailed    RunStatus = "failed"
)

// ExternalIP is the optional public-IP observation.
type ExternalIP struct {
	Provider        string     `json:"provider"`
	ProviderURL     string     `json:"providerUrl"`
	Before          string     `json:"before,omitempty"`
	After           string     `json:"after,omitempty"`
	Country         string     `json:"country,omitempty"`
	Error           string     `json:"error,omitempty"`
	Changed         bool       `json:"changed"`
	PreviousIP      string     `json:"previousIp,omitempty"`
	PreviousRunID   string     `json:"previousRunId,omitempty"`
	PreviousAt      *time.Time `json:"previousAt,omitempty"`
	PreviousProfile string     `json:"previousProfile,omitempty"`
	PreviousCountry string     `json:"previousCountry,omitempty"`
	Comparison      string     `json:"comparison,omitempty"`
	AfterCountry    string     `json:"afterCountry,omitempty"`
}

// Counts summarises outcomes of a run.
type Counts struct {
	Planned    int `json:"planned"`
	Probed     int `json:"probed"`
	TLSOK      int `json:"tlsOk"`
	HTTPSTotal int `json:"httpsTotal"`
	HTTPMatch  int `json:"httpMatch"`
	Errors     int `json:"errors"`
	Limited    int `json:"limited"`
	Skipped    int `json:"skipped"`
}

// Run is one complete check run.
type Run struct {
	SchemaVersion  int           `json:"schemaVersion"`
	ID             string        `json:"id"`
	ProfileName    string        `json:"profileName"`
	StartedAt      time.Time     `json:"startedAt"`
	FinishedAt     *time.Time    `json:"finishedAt"`
	AppVersion     string        `json:"appVersion"`
	Mode           RunMode       `json:"mode"`
	Route          RouteConfig   `json:"route"`
	IPFamily       IPFamily      `json:"ipFamily"`
	SystemProxy    string        `json:"systemProxyHint,omitempty"`
	Endpoints      []Endpoint    `json:"endpoints"`
	Results        []ProbeResult `json:"results"`
	Status         RunStatus     `json:"status"`
	ExternalIP     *ExternalIP   `json:"externalIp,omitempty"`
	Counts         Counts        `json:"counts"`
	MedianTLSReady *float64      `json:"medianTlsReadyMs"`
	Message        string        `json:"message,omitempty"`
	// AltRoute is the second route probed in diag mode.
	AltRoute *RouteConfig `json:"altRoute,omitempty"`
	// Environment is the network passport captured at run start (sysenv.Passport).
	Environment json.RawMessage `json:"environment,omitempty"`
	// Verdicts are per-group diagnostic conclusions.
	Verdicts []Verdict `json:"verdicts,omitempty"`
	// Splits are the split-routing checks ("home country direct, the rest via
	// VPN"), one per selected profile (ru-direct, cn-direct, ir-direct).
	Splits []*SplitCheck `json:"splits,omitempty"`
	// Split is the Russian check as stored by version 4.3 (read-only now).
	Split *SplitCheck `json:"split,omitempty"`
}

// SplitCheck compares the address a Russian site sees with the address a
// foreign reference node sees through the same route. It only observes: the
// program never changes routes, proxies or the VPN client's rules.
type SplitCheck struct {
	Group       string `json:"group,omitempty"` // registry group; "" = ru-direct (version 4.3)
	Home        string `json:"home,omitempty"`  // home country; "" = RU (version 4.3)
	Source      string `json:"source"`
	SourceURL   string `json:"sourceUrl"`
	DomesticIP  string `json:"domesticIp,omitempty"`
	DomesticVPN *bool  `json:"domesticVpn,omitempty"` // the source's own "this is a VPN/hosting" flag
	// DomesticCountry is the country of DomesticIP (RIPEstat geolocation, or the
	// Cloudflare country when both addresses are the same).
	DomesticCountry string `json:"domesticCountry,omitempty"`
	ForeignIP       string `json:"foreignIp,omitempty"`
	ForeignCountry  string `json:"foreignCountry,omitempty"`
	// Code: split_ok | all_vpn | all_direct | same_exit | foreign_in_home | domestic_foreign | domestic_vpn | unknown
	// (foreign_in_ru in runs of version 4.3).
	Code  string `json:"code"`
	Error string `json:"error,omitempty"`
}

// RunSummary is the lightweight history entry.
type RunSummary struct {
	ID             string      `json:"id"`
	ProfileName    string      `json:"profileName"`
	StartedAt      time.Time   `json:"startedAt"`
	Mode           RunMode     `json:"mode"`
	Route          RouteConfig `json:"route"`
	IPFamily       IPFamily    `json:"ipFamily"`
	Status         RunStatus   `json:"status"`
	Counts         Counts      `json:"counts"`
	MedianTLSReady *float64    `json:"medianTlsReadyMs"`
	AppVersion     string      `json:"appVersion"`
	// ExitIP is the public IP seen at the end of the run (or at its start).
	ExitIP      string `json:"exitIp,omitempty"`
	ExitCountry string `json:"exitCountry,omitempty"`
	ExitFrom    string `json:"exitFrom,omitempty"` // the IP at the start, when it changed during the run
	ExitKnown   bool   `json:"exitKnown,omitempty"`
}

// SplitFor returns the split-routing check of a group, also from 4.3 runs.
func (r *Run) SplitFor(group string) *SplitCheck {
	for _, s := range r.Splits {
		if s.Group == group {
			return s
		}
	}
	if group == "ru-direct" {
		return r.Split
	}
	return nil
}

// Summary builds the history entry for a run.
func (r *Run) Summary() RunSummary {
	return RunSummary{
		ID:             r.ID,
		ProfileName:    r.ProfileName,
		StartedAt:      r.StartedAt,
		Mode:           r.Mode,
		Route:          r.Route,
		IPFamily:       r.IPFamily,
		Status:         r.Status,
		Counts:         r.Counts,
		MedianTLSReady: r.MedianTLSReady,
		AppVersion:     r.AppVersion,
		ExitKnown:      true,
	}.withExit(r.ExternalIP)
}

func (s RunSummary) withExit(x *ExternalIP) RunSummary {
	if x == nil {
		return s
	}
	s.ExitIP = x.After
	s.ExitCountry = x.AfterCountry
	if s.ExitIP == "" {
		s.ExitIP = x.Before
	}
	if s.ExitCountry == "" {
		s.ExitCountry = x.Country
	}
	if x.Changed && x.Before != "" {
		s.ExitFrom = x.Before
	}
	return s
}

// Ms converts a duration to a millisecond pointer with 0.1 ms precision.
func Ms(d time.Duration) *float64 {
	v := float64(d.Microseconds()) / 1000
	v = float64(int64(v*10+0.5)) / 10
	return &v
}
