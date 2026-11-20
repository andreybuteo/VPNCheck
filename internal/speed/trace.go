package speed

import (
	"vpncheck/internal/runner"
)

// TraceURL is the public-IP page shared with the probe runs.
var TraceURL = runner.ExternalIPProvider.URL

func parseTraceIP(s string) (string, string) { return runner.ParseTrace(s) }
