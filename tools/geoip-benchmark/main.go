// Command geoip-benchmark measures identical million-line workloads with/without
// local MMDBs. It never downloads data. Default DBs are synthetic test fixtures.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"
	"webaudit/audit"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	lines := flag.Int("lines", 1000000, "Number of synthetic requests")
	scenario := flag.String("scenario", "repeated_mixed", "repeated_mixed or distinct_mixed")
	enabled := flag.Bool("geoip", false, "Enable local GeoIP")
	country := flag.String("country", "audit/testdata/geoip/country.mmdb", "Local Country DB")
	asn := flag.String("asn", "audit/testdata/geoip/asn.mmdb", "Local ASN DB")
	flag.Parse()
	if *lines < 1 || (*scenario != "repeated_mixed" && *scenario != "distinct_mixed") {
		return fmt.Errorf("invalid benchmark parameters")
	}
	dir, e := os.MkdirTemp("", "webaudit-geoip-bench-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "access.log")
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	w := bufio.NewWriterSize(f, 1<<20)
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < *lines; i++ {
		ip := "8.8.8.8"
		if i%2 == 1 {
			ip = "2606:4700::1111"
		}
		if *scenario == "distinct_mixed" {
			n := i / 2
			if i%2 == 0 {
				ip = fmt.Sprintf("11.%d.%d.%d", (n>>16)&255, (n>>8)&255, n&255)
			} else {
				ip = fmt.Sprintf("2600:100::%x:%x", n>>16, n&65535)
			}
		}
		if _, e = fmt.Fprintf(w, "%s - - [%s] \"GET /api/items HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0\"\n", ip, start.Add(time.Duration(i/320)*time.Second).Format("02/Jan/2006:15:04:05 -0700")); e != nil {
			f.Close()
			return e
		}
	}
	if e = w.Flush(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	st, _ := os.Stat(path)
	runtime.GC()
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	totalStart := time.Now()
	var g *audit.GeoIP
	var openElapsed time.Duration
	if *enabled {
		t := time.Now()
		g, e = audit.OpenGeoIP(*country, *asn, "", 4096)
		openElapsed = time.Since(t)
		if e != nil {
			close(stop)
			<-done
			return e
		}
		defer g.Close()
	}
	t := time.Now()
	r := audit.Analyze([]string{path}, audit.Options{GeoIP: g, Now: func() time.Time { return start }})
	analysisElapsed := time.Since(t)
	totalElapsed := time.Since(totalStart)
	close(stop)
	<-done
	var result []any
	for _, f := range r.Findings {
		result = append(result, struct {
			ID, IP, Severity string
			Score            int
			Count            int64
			Outcome          audit.Outcome
			Categories       []string
		}{f.ID, f.IP, f.Severity, f.Score, f.Count, f.Outcome, f.Categories})
	}
	b, _ := json.Marshal(result)
	sum := sha256.Sum256(b)
	rss, rssErr := peakRSS()
	rssError := ""
	if rssErr != nil {
		rssError = rssErr.Error()
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"scenario": *scenario, "geoip_enabled": *enabled, "lines": *lines, "input_bytes": st.Size(), "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "db_open_seconds": openElapsed.Seconds(), "analysis_seconds": analysisElapsed.Seconds(), "total_seconds": totalElapsed.Seconds(), "peak_sampled_go_heap_bytes": peak.Load(), "peak_process_resident_bytes": rss, "rss_error": rssError, "geoip_metrics": g.Metrics(), "parsed": r.Parsed, "unparsed": r.Unparsed, "partial": r.Partial, "incidents": len(r.Findings), "detection_sha256": hex.EncodeToString(sum[:]), "warnings": r.Warnings})
}
