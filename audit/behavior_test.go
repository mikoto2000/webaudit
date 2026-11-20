package audit

import (
	"fmt"
	"testing"
	"time"
)

func sample(i int) Event {
	return Event{IP: "192.0.2.1", Time: time.Unix(1793491200+int64(i), 0).UTC(), Target: fmt.Sprintf("/item/%d", i), Path: fmt.Sprintf("/item/%d", i), Method: ptr("GET"), Status: ptr(200), Bytes: ptr(int64(100)), UA: ptr("Browser"), Raw: fmt.Sprint(i)}
}
func hasSignal(s []Signal, id string) bool {
	for _, x := range s {
		if x.Rule.ID == id {
			return true
		}
	}
	return false
}
func TestBehavior(t *testing.T) {
	cases := []struct {
		name, id string
		n        int
		change   func(*Event, int)
	}{
		{"404", "WB-404", 21, func(e *Event, i int) { e.Status = ptr(404) }},
		{"authorization", "WB-auth", 21, func(e *Event, i int) { e.Status = ptr(403) }},
		{"login", "WB-login", 21, func(e *Event, i int) { e.Path = "/login"; e.Target = "/login"; e.Method = ptr("POST") }},
		{"rate", "WB-rate", 601, func(e *Event, i int) { e.Time = sample(0).Time; e.Path = "/api/poll" }},
		{"paths", "WB-paths", 41, func(e *Event, i int) { e.Status = ptr(404) }},
		{"sensitive", "WB-sensitive", 6, func(e *Event, i int) { e.Target = fmt.Sprintf("/.env.%d", i); e.Path = e.Target }},
		{"ua", "WB-ua", 21, func(e *Event, i int) { e.Status = ptr(404); e.UA = ptr(fmt.Sprint(i)) }},
		{"categories", "WB-multi", 8, func(e *Event, i int) {
			if i%2 == 0 {
				e.Target = "/.env"
			} else {
				e.Target = "/?q=<script>"
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := NewAnalysis(Options{})
			for i := 0; i < c.n; i++ {
				e := sample(i % 200)
				c.change(&e, i)
				h, _ := Detect(e)
				a.Observe(e, h)
			}
			if !hasSignal(a.Finish(), c.id) {
				t.Fatal("missing", c.id)
			}
		})
	}
	a := NewAnalysis(Options{})
	for i := 0; i < 21; i++ {
		e := sample(i * 360)
		e.Status = ptr(404)
		a.Observe(e, nil)
	}
	if hasSignal(a.Finish(), "WB-404") {
		t.Fatal("ignored time windows")
	}
	a = NewAnalysis(Options{})
	for i := 0; i < 100; i++ {
		e := sample(i)
		e.Path = "/wp-admin/"
		a.Observe(e, nil)
	}
	if len(a.Finish()) != 0 {
		t.Fatal("normal administration")
	}
}
func TestLeaky(t *testing.T) {
	b := Leaky{Capacity: 5, LeakEvery: 10 * time.Second}
	now := sample(0).Time
	for i := 0; i < 5; i++ {
		if b.Add(now) {
			t.Fatal("early overflow")
		}
	}
	if !b.Add(now) {
		t.Fatal("no overflow")
	}
	if b.Add(now.Add(time.Minute)) {
		t.Fatal("did not leak")
	}
	if b.Add(now.Add(-time.Minute)) {
		t.Fatal("late event should abstain")
	}
}
func TestStatistics(t *testing.T) {
	a := NewAnalysis(Options{})
	for i := 0; i < 21; i++ {
		for j := 0; j < 25; j++ {
			e := sample(j)
			e.IP = fmt.Sprintf("192.0.2.%d", i+1)
			a.Observe(e, nil)
		}
	}
	for i := 0; i < 250; i++ {
		e := sample(i)
		e.IP = "192.0.2.250"
		e.Status = ptr(500)
		e.Bytes = ptr(int64(100000))
		a.Observe(e, nil)
	}
	s := a.Finish()
	if !hasSignal(s, "WS-ip") || !hasSignal(s, "WS-errors") {
		t.Fatalf("%+v", s)
	}
	a = NewAnalysis(Options{})
	for i := 0; i < 30; i++ {
		e := sample(i)
		e.Path = "/download"
		a.Observe(e, nil)
	}
	e := sample(31)
	e.Path = "/download"
	e.Bytes = ptr(int64(1000000))
	a.Observe(e, nil)
	if !hasSignal(a.Finish(), "WS-url-size") {
		t.Fatal("missing URL baseline anomaly")
	}
	a = NewAnalysis(Options{})
	for i := 0; i < 30; i++ {
		e := sample(0)
		e.Time = e.Time.Add(time.Duration(i) * time.Hour)
		a.Observe(e, nil)
	}
	for j := 0; j < 200; j++ {
		e := sample(0)
		e.Time = e.Time.Add(31 * time.Hour)
		a.Observe(e, nil)
	}
	if !hasSignal(a.Finish(), "WS-hour") {
		t.Fatal("hourly anomaly")
	}
	a = NewAnalysis(Options{})
	a.Observe(sample(0), nil)
	if len(a.Finish()) != 0 {
		t.Fatal("insufficient baseline must abstain")
	}
}
func TestAnalysisBoundsAndReorder(t *testing.T) {
	a := NewAnalysis(Options{MaxKeys: 2, MaxFindings: 3})
	for i := 0; i < 100; i++ {
		e := sample(i)
		e.IP = fmt.Sprintf("192.0.2.%d", i+1)
		a.Observe(e, nil)
	}
	if len(a.Warnings()) == 0 {
		t.Fatal("silent limit")
	}
	if len(a.Finish()) > 3 {
		t.Fatal("unbounded findings")
	}
	a = NewAnalysis(Options{})
	for i := 20; i >= 0; i-- {
		e := sample(i)
		e.Status = ptr(404)
		a.Observe(e, nil)
	}
	if !hasSignal(a.Finish(), "WB-404") {
		t.Fatal("reorder")
	}
}
