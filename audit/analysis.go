package audit

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Signal struct {
	Rule   Rule      `json:"rule"`
	Event  Event     `json:"event"`
	Count  int64     `json:"count"`
	Reason string    `json:"reason"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
}
type Leaky struct {
	Capacity  float64
	LeakEvery time.Duration
	Level     float64
	last      time.Time
}

func (b *Leaky) Add(t time.Time) bool {
	if !b.last.IsZero() && t.Before(b.last) {
		return false
	}
	if b.LeakEvery <= 0 {
		return false
	}
	if !b.last.IsZero() {
		b.Level = math.Max(0, b.Level-t.Sub(b.last).Seconds()/b.LeakEvery.Seconds())
	}
	b.last = t
	b.Level++
	return b.Level > b.Capacity
}

type window struct {
	n, n404, auth, login              int64
	paths, uas, categories, sensitive map[string]bool
	sample                            Event
	first, last                       time.Time
	leak                              Leaky
	burst                             bool
}
type peer struct {
	first, last                time.Time
	n, errors, statusN, bytesN int64
	bytes                      float64
	sample                     Event
}
type baseline struct {
	values []float64
	next   int
	sample Event
}
type Analysis struct {
	o        Options
	windows  map[string]*window
	ips      map[string]*peer
	urls     map[string]*baseline
	hours    map[int64]*peer
	global   baseline
	signals  []Signal
	warnings []string
	last     time.Time
}

func NewAnalysis(o Options) *Analysis {
	return &Analysis{o: o.defaults(), windows: map[string]*window{}, ips: map[string]*peer{}, urls: map[string]*baseline{}, hours: map[int64]*peer{}}
}
func (a *Analysis) warn(s string) {
	for _, w := range a.warnings {
		if w == s {
			return
		}
	}
	a.warnings = append(a.warnings, s)
}
func (a *Analysis) Warnings() []string { return append([]string(nil), a.warnings...) }
func (a *Analysis) allow(n int) bool {
	if n >= a.o.MaxKeys {
		a.warn("Tracked-key limit reached; behavior/statistical coverage is incomplete")
		return false
	}
	return true
}
func (a *Analysis) distinct(m map[string]bool, k string) {
	k = digest(k)
	if m[k] {
		return
	}
	if len(m) >= 64 {
		a.warn("Distinct-value limit reached; diversity counts are lower bounds")
		return
	}
	m[k] = true
}
func behaviorRule(id, desc string) Rule {
	return Rule{ID: id, Category: strings.TrimPrefix(id, "WB-"), Severity: "medium", Description: desc, Required: []string{"ip", "time"}, Source: "docs/rule-inventory.md"}
}
func (a *Analysis) emit(id, desc string, e Event, n int64, reason string, start, end time.Time) {
	if len(a.signals) >= a.o.MaxFindings {
		a.warn("Signal limit reached; findings are incomplete")
		return
	}
	a.signals = append(a.signals, Signal{Rule: behaviorRule(id, desc), Event: compactEvent(e), Count: n, Reason: reason, Start: start, End: end})
}
func (a *Analysis) Observe(e Event, hits []Rule) {
	if !a.last.IsZero() && e.Time.Before(a.last) {
		a.warn("Input timestamps are out of order; event-time windows retained within key budget, online size baselines and leaky buckets are order-sensitive")
	}
	a.last = e.Time
	host := val(e.Host)
	key := digest(e.IP + "\x00" + host)
	// Two overlapping 5-minute partitions reduce boundary misses, while remaining
	// deterministic for shuffled files. This is not an exact rolling window.
	for _, shift := range []int64{0, 150} {
		slot := (e.Time.Unix() - shift) / 300
		wk := key + "\x00" + strconv.FormatInt(slot, 10) + "/" + strconv.FormatInt(shift, 10)
		w := a.windows[wk]
		if w == nil {
			if !a.allow(len(a.windows)) {
				continue
			}
			w = &window{paths: map[string]bool{}, uas: map[string]bool{}, categories: map[string]bool{}, sensitive: map[string]bool{}, sample: compactEvent(e), first: e.Time, last: e.Time, leak: Leaky{Capacity: 300, LeakEvery: time.Second}}
			a.windows[wk] = w
		}
		w.n++
		if e.Time.Before(w.first) {
			w.first = e.Time
		}
		if e.Time.After(w.last) {
			w.last = e.Time
		}
		status := val(e.Status)
		if status == 404 {
			w.n404++
		}
		if status == 401 || status == 403 {
			w.auth++
		}
		if val(e.Method) == "POST" && isLogin(e.Path) {
			w.login++
		}
		a.distinct(w.paths, e.Path)
		if e.UA != nil {
			a.distinct(w.uas, *e.UA)
		}
		for _, h := range hits {
			a.distinct(w.categories, h.Category)
			if h.Category == "sensitive_file" {
				a.distinct(w.sensitive, e.Path)
			}
		}
		if w.leak.Add(e.Time) {
			w.burst = true
		}
	}
	p := a.ips[key]
	if p == nil && a.allow(len(a.ips)) {
		p = &peer{sample: compactEvent(e), first: e.Time, last: e.Time}
		a.ips[key] = p
	}
	if p != nil {
		p.n++
		if e.Time.Before(p.first) {
			p.first = e.Time
		}
		if e.Time.After(p.last) {
			p.last = e.Time
		}
		if e.Status != nil {
			p.statusN++
		}
		if e.Bytes != nil {
			p.bytesN++
		}
		if val(e.Status) >= 400 {
			p.errors++
		}
		p.bytes += float64(val(e.Bytes))
	}
	hour := e.Time.Unix() / 3600
	hp := a.hours[hour]
	if hp == nil && a.allow(len(a.hours)) {
		hp = &peer{sample: compactEvent(e), first: e.Time, last: e.Time}
		a.hours[hour] = hp
	}
	if hp != nil {
		hp.n++
		if e.Time.Before(hp.first) {
			hp.first = e.Time
		}
		if e.Time.After(hp.last) {
			hp.last = e.Time
		}
	}
	if e.Bytes != nil && e.Status != nil {
		value := float64(*e.Bytes)
		uk := host + "\x00" + val(e.Method) + "\x00" + e.Path + "\x00" + strconv.Itoa(*e.Status)
		uk = digest(uk)
		b := a.urls[uk]
		if b == nil && a.allow(len(a.urls)) {
			b = &baseline{sample: compactEvent(e)}
			a.urls[uk] = b
		}
		if b != nil {
			if isOutlier(value, b.values, 4096, 5) {
				a.emit("WS-url-size", "Response differs from same URL/status baseline", e, 1, "At least 20 prior size samples; >median+6*MAD, >5x median and >4096 bytes difference", e.Time, e.Time)
			}
			b.add(value)
		}
		if isOutlier(value, a.global.values, 1<<20, 10) {
			a.emit("WS-size", "Unusually large response", e, 1, "At least 20 prior samples; robust size threshold plus 1 MiB and 10x effect floors", e.Time, e.Time)
		}
		a.global.add(value)
	}
}
func isLogin(path string) bool {
	p := strings.ToLower(path)
	return p == "/login" || p == "/signin" || strings.HasSuffix(p, "/wp-login.php") || strings.HasSuffix(p, "/login")
}
func (b *baseline) add(v float64) {
	if len(b.values) < 128 {
		b.values = append(b.values, v)
	} else {
		b.values[b.next] = v
		b.next = (b.next + 1) % 128
	}
}
func median(v []float64) float64 {
	x := append([]float64(nil), v...)
	sort.Float64s(x)
	if len(x) == 0 {
		return 0
	}
	i := len(x) / 2
	if len(x)%2 == 0 {
		return (x[i-1] + x[i]) / 2
	}
	return x[i]
}
func isOutlier(v float64, base []float64, floor, ratio float64) bool {
	return newOutlierBaseline(base).isOutlier(v, floor, ratio)
}

// A fixed peer population shares one median/MAD calculation. Online size
// populations change per observation and continue to use isOutlier above.
type outlierBaseline struct {
	count       int
	median, mad float64
}

func newOutlierBaseline(base []float64) outlierBaseline {
	if len(base) < 20 {
		return outlierBaseline{count: len(base)}
	}
	m := median(base)
	d := make([]float64, len(base))
	for i, x := range base {
		d[i] = math.Abs(x - m)
	}
	return outlierBaseline{count: len(base), median: m, mad: median(d)}
}

func (b outlierBaseline) isOutlier(v, floor, ratio float64) bool {
	return b.count >= 20 && v > b.median+math.Max(floor, 6*1.4826*b.mad) && v > b.median*ratio
}
func (a *Analysis) Finish() []Signal {
	keys := make([]string, 0, len(a.windows))
	for k := range a.windows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w := a.windows[k]
		emit := func(id, desc string, n int64) {
			a.emit(id, desc, w.sample, n, fmt.Sprintf("%d observations in overlapping five-minute event-time window; diversity bounded at 64", n), w.first, w.last)
		}
		if w.n404 >= 20 {
			emit("WB-404", "Concentrated HTTP 404 responses", w.n404)
		}
		if w.auth >= 20 {
			emit("WB-auth", "Concentrated HTTP 401/403 responses", w.auth)
		}
		if w.login >= 20 {
			emit("WB-login", "Repeated login endpoint requests", w.login)
		}
		if w.n >= 600 {
			emit("WB-rate", "High request rate (may be legitimate)", w.n)
		}
		if w.burst {
			emit("WB-burst", "Leaky bucket burst (capacity 300, leak 1/s)", w.n)
		}
		if len(w.paths) >= 40 && w.n404+w.auth >= 10 {
			emit("WB-paths", "Diverse URL probing with errors", int64(len(w.paths)))
		}
		if len(w.sensitive) >= 5 {
			emit("WB-sensitive", "Multiple distinct sensitive resources probed", int64(len(w.sensitive)))
		}
		if len(w.uas) >= 5 && len(w.paths) >= 10 && w.n404+w.auth >= 10 {
			emit("WB-ua", "User-Agent rotation during probing", int64(len(w.uas)))
		}
		if len(w.categories) >= 2 && w.n >= 8 {
			emit("WB-multi", "Multiple suspicious techniques in one activity window", int64(len(w.categories)))
		}
	}
	var counts, rates, bytes []float64
	for _, p := range a.ips {
		counts = append(counts, float64(p.n))
		if p.bytesN == p.n {
			bytes = append(bytes, p.bytes)
		}
		if p.statusN >= 20 {
			rates = append(rates, float64(p.errors)/float64(p.statusN))
		}
	}
	countBaseline := newOutlierBaseline(counts)
	byteBaseline := newOutlierBaseline(bytes)
	rateBaseline := newOutlierBaseline(rates)
	keys = keys[:0]
	for k := range a.ips {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := a.ips[k]
		if countBaseline.isOutlier(float64(p.n), 100, 5) || (p.bytesN == p.n && byteBaseline.isOutlier(p.bytes, 1<<20, 10)) {
			a.emit("WS-ip", "IP request/byte volume peer outlier", p.sample, p.n, "At least 20 peer groups; robust median/MAD and minimum effect size; not proof of exfiltration", p.first, p.last)
		}
		if p.statusN >= 20 && rateBaseline.isOutlier(float64(p.errors)/float64(p.statusN), 0.5, 3) {
			a.emit("WS-errors", "IP HTTP-error-rate peer outlier", p.sample, p.n, "At least 20 requests per peer and 20 peers; >0.5 rate difference plus robust threshold", p.first, p.last)
		}
	}
	if len(a.hours) >= 2 {
		lo, hi := int64(math.MaxInt64), int64(math.MinInt64)
		for h := range a.hours {
			if h < lo {
				lo = h
			}
			if h > hi {
				hi = h
			}
		}
		if hi-lo < int64(a.o.MaxKeys) {
			var baseline []float64
			for h := lo; h <= hi; h++ {
				var n int64
				if p := a.hours[h]; p != nil {
					n = p.n
				}
				baseline = append(baseline, float64(n))
			}
			hourBaseline := newOutlierBaseline(baseline)
			for h := lo; h <= hi; h++ {
				p := a.hours[h]
				if p != nil && hourBaseline.isOutlier(float64(p.n), 100, 5) {
					a.emit("WS-hour", "Hourly traffic peer outlier", p.sample, p.n, "Observed hours including zero bins; >=20 bins; robust threshold, +100 requests and 5x median", p.first, p.last)
				}
			}
		} else {
			a.warn("Hourly span exceeds bounded baseline; hourly anomalies withheld")
		}
	}
	if len(a.ips) < 20 {
		a.warn("Too few IP peers for request/error-rate statistical inference")
	}
	return append([]Signal(nil), a.signals...)
}
