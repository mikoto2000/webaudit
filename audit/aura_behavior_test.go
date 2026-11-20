package audit

import (
	"fmt"
	"testing"
)

func TestAuraSourceBehaviorThresholds(t *testing.T) {
	a := newAuraAnalysis(Options{})
	for i := 0; i < 19; i++ {
		a.Observe(sourceEvent(i))
	}
	if len(a.Finish()) != 0 {
		t.Fatal("19 failures must not reach the upstream threshold")
	}
	a.Observe(sourceEvent(19))
	out := a.Finish()
	if len(out) != 1 || out[0].RuleID != "brute_force" || out[0].Count != 20 {
		t.Fatal(out)
	}
	a = newAuraAnalysis(Options{})
	for i := 0; i < 50; i++ {
		e := sourceEvent(i * 400)
		e.Status = ptr(404)
		a.Observe(e)
	}
	out = a.Finish()
	if len(out) != 1 || out[0].RuleID != "enumeration_404" || out[0].Count != 50 {
		t.Fatal("404 threshold is case-wide", out)
	}
}
func TestAuraSourceStatisticalAggregates(t *testing.T) {
	a := newAuraAnalysis(Options{})
	for i := 0; i < 12; i++ {
		e := sourceEvent(i)
		e.Status = ptr(200)
		e.IP = fmt.Sprintf("192.0.2.%d", i+1)
		e.Bytes = ptr(int64(100))
		if i == 11 {
			e.Bytes = ptr(int64(20 * 1024 * 1024))
		}
		a.Observe(e)
	}
	out := a.Finish()
	if len(out) != 1 || out[0].RuleID != "exfil_bytes" || out[0].IP != "192.0.2.12" {
		t.Fatal(out)
	}
	a = newAuraAnalysis(Options{})
	for i := 0; i < 5; i++ {
		e := sourceEvent(i)
		e.Status = ptr(200)
		e.UA = ptr("RareBrowser")
		a.Observe(e)
	}
	out = a.Finish()
	if len(out) != 1 || out[0].RuleID != "rare_user_agent" || out[0].Count != 5 {
		t.Fatal(out)
	}
	e := sourceEvent(5)
	e.Status = ptr(200)
	e.UA = ptr("RareBrowser")
	a.Observe(e)
	if len(a.Finish()) != 0 {
		t.Fatal("six observations are not rare under the source definition")
	}
	a = newAuraAnalysis(Options{})
	for i := 0; i < 12; i++ {
		count := 1
		if i == 11 {
			count = 100
		}
		for j := 0; j < count; j++ {
			e := sourceEvent(i * 3600)
			e.Status = ptr(200)
			a.Observe(e)
		}
	}
	out = a.Finish()
	if len(out) != 1 || out[0].RuleID != "traffic_spike" || out[0].Count != 100 {
		t.Fatal(out)
	}
}
