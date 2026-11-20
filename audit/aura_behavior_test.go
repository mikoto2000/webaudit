package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestAuraExistingKeysContinueAtLimit(t *testing.T) {
	for _, tc := range []struct {
		status, max, count int
		rule               string
	}{
		{401, 4, 20, "brute_force"},
		{404, 3, 50, "enumeration_404"},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			a := newAuraAnalysis(Options{MaxKeys: tc.max})
			e := sourceEvent(0)
			e.Status, e.UA = ptr(tc.status), ptr("Browser")
			for i := 0; i < tc.count; i++ {
				a.Observe(e)
			}
			p := a.peers[e.IP]
			if p.Count != int64(tc.count) || a.hours[e.Time.Truncate(time.Hour).Unix()] != int64(tc.count) || a.uas[digest("Browser")].Count != int64(tc.count) {
				t.Fatal("existing aggregate stopped at key limit", p)
			}
			other := e
			other.IP = "192.0.2.99"
			a.Observe(other)
			if a.peers[other.IP] != nil || p.Count != int64(tc.count) || a.hours[e.Time.Truncate(time.Hour).Unix()] != int64(tc.count+1) || a.uas[digest("Browser")].Count != int64(tc.count+1) {
				t.Fatal("untracked peer must still update existing UA/hour aggregates")
			}
			for _, alert := range a.Finish() {
				if alert.RuleID == tc.rule && alert.Count == int64(tc.count) {
					return
				}
			}
			t.Fatal("missing threshold alert", a.Finish())
		})
	}
}

func TestAuraNewKeysStayBoundedAndWarn(t *testing.T) {
	for _, maxKeys := range []int{1, 2, 3, 4, 5} {
		t.Run(fmt.Sprint(maxKeys), func(t *testing.T) {
			a := newAuraAnalysis(Options{MaxKeys: maxKeys})
			first := sourceEvent(0)
			first.UA = ptr("Browser")
			a.Observe(first)
			for i := 1; i <= 10; i++ {
				e := first
				e.Time = e.Time.Add(time.Duration(i) * time.Hour)
				e.IP, e.UA = fmt.Sprintf("192.0.2.%d", i+1), ptr(fmt.Sprintf("Browser%d", i))
				a.Observe(e) // New peers, windows, UAs and hours must share the budget.
				e.IP = first.IP
				a.Observe(e) // Existing peer must not bypass the other tables' budgets.
				if n := len(a.peers) + len(a.windows) + len(a.uas) + len(a.hours); n > maxKeys {
					t.Fatalf("keys=%d, max=%d", n, maxKeys)
				}
			}
			a.Observe(first)
			if a.peers[first.IP].Count != 12 || len(a.warnings) != 1 {
				t.Fatal(a.peers[first.IP], a.warnings)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "access.log")
	line := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "POST /login HTTP/1.1" 401 0 "-" "Browser"` + "\n"
	if err := os.WriteFile(path, []byte(strings.Repeat(line, 20)), 0600); err != nil {
		t.Fatal(err)
	}
	r := Analyze([]string{path}, Options{MaxKeys: 1})
	if !r.Partial || !strings.Contains(strings.Join(r.Warnings, "\n"), "Aura aggregation limit reached") {
		t.Fatal("limit must surface in report", r.Warnings)
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
