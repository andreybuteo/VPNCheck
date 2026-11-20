package api

import (
	"sort"
	"sync"
	"time"

	"vpncheck/internal/model"
)

// IPLogSize is the number of entries in the exit-IP strip.
const IPLogSize = 10

// ipEntry is one observation of the public exit IP.
type ipEntry struct {
	At      time.Time         `json:"at"`
	Kind    string            `json:"kind"` // run | speed
	ID      string            `json:"id"`
	IP      string            `json:"ip"`
	From    string            `json:"from,omitempty"` // IP at the start when it changed during a run
	Country string            `json:"country,omitempty"`
	Profile string            `json:"profile,omitempty"`
	Route   model.RouteConfig `json:"route"`
}

// exitCache remembers the exit IP of runs saved before 3.0 (their index
// entries do not carry it), so each old run file is read once.
var exitCache sync.Map // run id -> model.RunSummary exit fields

func (a *API) ipLogOn() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.settings.IPLogOff
}

func (a *API) ipLog() map[string]any {
	out := map[string]any{"enabled": a.ipLogOn(), "size": IPLogSize, "entries": []ipEntry{}}
	var list []ipEntry
	runs, _ := a.d.Store.ListRuns()
	checked := 0
	for _, s := range runs {
		if checked >= 40 || len(list) >= IPLogSize {
			break
		}
		checked++
		if !s.ExitKnown {
			if c, ok := exitCache.Load(s.ID); ok {
				s = c.(model.RunSummary)
			} else if run, err := a.d.Store.LoadRun(s.ID); err == nil {
				s = run.Summary()
				exitCache.Store(s.ID, s)
			}
		}
		if s.ExitIP == "" {
			continue
		}
		list = append(list, ipEntry{At: s.StartedAt, Kind: "run", ID: s.ID, IP: s.ExitIP, From: s.ExitFrom, Country: s.ExitCountry, Profile: s.ProfileName, Route: s.Route})
	}
	if a.d.Speed != nil {
		n := 0
		for _, r := range a.d.Speed.History() {
			if n >= IPLogSize {
				break
			}
			if r.ExitIP == "" {
				continue
			}
			n++
			list = append(list, ipEntry{At: r.StartedAt, Kind: "speed", ID: r.ID, IP: r.ExitIP, Country: r.ExitCountry, Profile: r.ProfileName, Route: r.Route})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].At.After(list[j].At) })
	if len(list) > IPLogSize {
		list = list[:IPLogSize]
	}
	// oldest first: the strip reads left to right like a timeline
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	if list != nil {
		out["entries"] = list
	}
	return out
}
