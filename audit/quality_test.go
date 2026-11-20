package audit

import (
	"strings"
	"testing"
	"time"
)

func TestProtocolAllowlist(t *testing.T) {
	for _, p := range []string{"HTTP/9.9", "HTTP/10.0", "HTTP/1.99", "HTTP/0.1"} {
		h, _ := Detect(Event{Protocol: ptr(p)})
		if len(h) == 0 {
			t.Fatal(p)
		}
	}
	for _, p := range []string{"HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3", "HTTP/3.0"} {
		h, _ := Detect(Event{Protocol: ptr(p)})
		if len(h) != 0 {
			t.Fatal(p)
		}
	}
}
func TestClockInjection(t *testing.T) {
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	r := Stream(nil, Options{Now: func() time.Time { return now }}, func(Event) {})
	if !r.AnalyzedAt.Equal(now) {
		t.Fatal(r.AnalyzedAt)
	}
}
func TestEvidenceBudget(t *testing.T) {
	c := NewCorrelator(Options{MaxEvidenceBytes: 1000})
	e := incidentEvent(0, 200)
	e.Raw = strings.Repeat("x", 4000)
	h, n := Detect(e)
	c.Add(e, h, n)
	f := c.Finish()
	if len(c.Warnings()) == 0 || len(f[0].Evidence) > 0 {
		t.Fatal("evidence budget ignored")
	}
}
func TestMissingStatusIsNotZeroErrorBaseline(t *testing.T) {
	a := NewAnalysis(Options{})
	for i := 0; i < 21; i++ {
		for j := 0; j < 25; j++ {
			e := sample(j)
			e.IP = string(rune('a' + i))
			e.Status = nil
			a.Observe(e, nil)
		}
	}
	for j := 0; j < 25; j++ {
		e := sample(j)
		e.IP = "peer"
		e.Status = ptr(500)
		a.Observe(e, nil)
	}
	if hasSignal(a.Finish(), "WS-errors") {
		t.Fatal("missing status used as zero-error peers")
	}
}
func TestStatisticalPeriod(t *testing.T) {
	a := NewAnalysis(Options{})
	for i := 0; i < 21; i++ {
		e := sample(0)
		e.IP = string(rune('a' + i))
		a.Observe(e, nil)
	}
	for j := 0; j < 250; j++ {
		e := sample(j)
		e.IP = "outlier"
		a.Observe(e, nil)
	}
	for _, s := range a.Finish() {
		if s.Rule.ID == "WS-ip" && s.Event.IP == "outlier" {
			if !s.End.Equal(sample(249).Time) {
				t.Fatal("incorrect statistical period", s.Start, s.End)
			}
			return
		}
	}
	t.Fatal("no outlier")
}
