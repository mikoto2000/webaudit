package audit

import (
	"testing"
	"time"
)

func TestOutlierThresholds(t *testing.T) {
	base := make([]float64, 20)
	for i := range base {
		base[i] = float64(20 - i) // median 10.5, MAD 5; intentionally unsorted.
	}
	for _, tc := range []struct {
		name                string
		n                   int
		value, floor, ratio float64
		want                bool
	}{
		{"insufficient", 19, 1000, 0, 1, false},
		{"below MAD", 20, 54, 0, 1, false},
		{"above MAD", 20, 55, 0, 1, true},
		{"at effect floor", 20, 110.5, 100, 1, false},
		{"above effect floor", 20, 111, 100, 1, true},
		{"at ratio", 20, 105, 0, 10, false},
		{"above ratio", 20, 106, 0, 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := newOutlierBaseline(base[:tc.n])
			if got := stats.isOutlier(tc.value, tc.floor, tc.ratio); got != tc.want {
				t.Fatalf("fixed population: got %v, want %v", got, tc.want)
			}
			if got := isOutlier(tc.value, base[:tc.n], tc.floor, tc.ratio); got != tc.want {
				t.Fatalf("online population: got %v, want %v", got, tc.want)
			}
		})
	}
	for i, v := range base {
		if v != float64(20-i) {
			t.Fatal("baseline reordered")
		}
	}
}

func TestFinishBytePopulationExcludesMissingSizes(t *testing.T) {
	for _, complete := range []int{18, 19} {
		a := NewAnalysis(Options{})
		for i := 0; i < 25; i++ {
			e := sample(0)
			e.IP = string(rune('a' + i))
			p := &peer{sample: e, n: 25, bytesN: 24, bytes: 2500}
			if i < complete {
				p.bytesN = 25
			}
			a.ips[e.IP] = p
		}
		e := sample(0)
		e.IP = "large-response-peer"
		a.ips[e.IP] = &peer{sample: e, n: 25, bytesN: 25, bytes: 2 << 20}
		if got, want := hasSignal(a.Finish(), "WS-ip"), complete == 19; got != want {
			t.Fatalf("%d complete peers plus candidate: outlier=%v, want %v", complete, got, want)
		}
	}
}

func TestFinishHourlyBaselineIncludesEmptyHours(t *testing.T) {
	a := NewAnalysis(Options{})
	e := sample(0)
	h := e.Time.Unix() / 3600
	// Twenty bins with only two occupied hours: the empty bins are needed
	// both to reach the minimum population and to establish a zero median.
	a.hours[h] = &peer{sample: e, n: 1}
	last := e
	last.Time = e.Time.Add(19 * time.Hour)
	a.hours[h+19] = &peer{sample: last, n: 200}
	if !hasSignal(a.Finish(), "WS-hour") {
		t.Fatal("empty hours excluded from statistical population")
	}
}
