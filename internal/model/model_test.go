package model

import "testing"

func TestSplitForAndExitCountry(t *testing.T) {
	legacy := &SplitCheck{}
	current := &SplitCheck{Group: "ru-direct"}
	r := Run{Split: legacy, Splits: []*SplitCheck{nil, current}}
	if r.SplitFor("ru-direct") != current || r.SplitFor("cn-direct") != nil {
		t.Fatal("wrong split precedence")
	}
	r.Splits = nil
	if r.SplitFor("ru-direct") != legacy {
		t.Fatal("legacy split lost")
	}
	x := &ExternalIP{Before: "192.0.2.1", Country: "DE", After: "192.0.2.2"}
	r.ExternalIP = x
	if r.Summary().ExitCountry != "" {
		t.Fatal("country from a different exit")
	}
	x.After = x.Before
	if r.Summary().ExitCountry != "DE" {
		t.Fatal("country lost for unchanged legacy exit")
	}
}
