package runner

import (
	"vpncheck/internal/diag"
	"vpncheck/internal/model"
)

// compareAnthropicIP runs before the current run is saved to history.
func (r *Runner) compareAnthropicIP(run *model.Run) {
	if run.ExternalIP == nil {
		return
	}
	hasAnthropic := false
	for _, e := range run.Endpoints {
		if e.GroupID == "anthropic" {
			hasAnthropic = true
		}
	}
	if !hasAnthropic {
		return
	}
	x := run.ExternalIP
	x.Comparison = "no_baseline"
	if r.d.Store == nil {
		return
	}
	history, err := r.d.Store.ListRuns()
	if err != nil {
		x.Comparison = "history_unavailable"
		return
	}
	for _, summary := range history {
		if summary.ID == run.ID || !summary.StartedAt.Before(run.StartedAt) {
			continue
		}
		old, err := r.d.Store.LoadRun(summary.ID)
		if err != nil || old.Status != model.RunCompleted || !diag.AnthropicNetworkOK(old) {
			continue
		}
		x.PreviousRunID, x.PreviousAt, x.PreviousProfile = old.ID, &old.StartedAt, old.ProfileName
		x.Comparison = "previous_ip_unknown"
		if old.ExternalIP != nil && !old.ExternalIP.Changed && old.ExternalIP.Before != "" && old.ExternalIP.After == old.ExternalIP.Before {
			x.PreviousIP, x.PreviousCountry = old.ExternalIP.After, old.ExternalIP.AfterCountry
			if x.PreviousCountry == "" {
				x.PreviousCountry = old.ExternalIP.Country
			}
		}
		if x.PreviousIP != "" {
			switch {
			case x.Before == "" || x.After == "":
				x.Comparison = "current_ip_unknown"
			case x.Changed:
				x.Comparison = "changed_during_run"
			case x.After == x.PreviousIP:
				x.Comparison = "same"
			default:
				x.Comparison = "different"
			}
		}
		return
	}
}
