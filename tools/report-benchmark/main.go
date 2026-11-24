// Command report-benchmark measures legacy analysis and bounded report generation
// on the same synthetic input. Measurements are not production sizing guarantees.
package main

import (
	"bufio"
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
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	n := flag.Int("lines", 100000, "synthetic observations")
	mode := flag.String("mode", "bundle", "bundle or analysis")
	attack := flag.Bool("mixed", false, "every fifth request probes a sensitive file")
	capBytes := flag.Int64("spool-bytes", 16<<20, "private spool cap")
	flag.Parse()
	if *n < 1 || (*mode != "bundle" && *mode != "analysis") || *capBytes < 1 {
		return fmt.Errorf("invalid arguments")
	}
	dir, err := os.MkdirTemp("", "webaudit-report-benchmark-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	input := filepath.Join(dir, "access.log")
	f, err := os.Create(input)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < *n; i++ {
		uri := fmt.Sprintf("/api/items/%d", i%32)
		status := 200
		if *attack && i%5 == 0 {
			uri = "/.env"
			status = 404
		}
		if _, err = fmt.Fprintf(w, "192.0.2.%d - - [%s] \"GET %s HTTP/1.1\" %d 100 \"-\" \"Browser\"\n", i%16+1, start.Add(time.Duration(i)*time.Second).Format("02/Jan/2006:15:04:05 -0700"), uri, status); err != nil {
			f.Close()
			return err
		}
	}
	if err = w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	st, err := os.Stat(input)
	if err != nil {
		return err
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peakHeap, peakSpool atomic.Uint64
	output := filepath.Join(dir, "report")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				var mem runtime.MemStats
				runtime.ReadMemStats(&mem)
				if mem.HeapAlloc > peakHeap.Load() {
					peakHeap.Store(mem.HeapAlloc)
				}
				paths, _ := filepath.Glob(filepath.Join(output, ".requests-*"))
				for _, p := range paths {
					if s, e := os.Stat(p); e == nil && uint64(s.Size()) > peakSpool.Load() {
						peakSpool.Store(uint64(s.Size()))
					}
				}
			}
		}
	}()
	began := time.Now()
	var parsed int64
	var complete bool
	var spool int64
	var evidenceComplete bool
	var warnings []string
	if *mode == "analysis" {
		r := audit.Analyze([]string{input}, audit.Options{})
		parsed = r.Parsed
		complete = !r.Partial
		warnings = r.Warnings
	} else {
		var r *audit.InvestigationReport
		r, err = audit.GenerateBundle([]string{input}, output, audit.Options{}, audit.BundleOptions{Language: "en", MaxSpoolBytes: *capBytes, MaxOutputBytes: 256 << 20})
		if r != nil {
			parsed = r.Analysis.Parsed
			complete = r.Complete
			spool = r.Evidence.SpoolBytes
			evidenceComplete = r.EvidenceComplete
			warnings = r.Analysis.Warnings
		}
	}
	elapsed := time.Since(began)
	close(stop)
	<-done
	if err != nil {
		return err
	}
	var finalBytes int64
	filepath.WalkDir(output, func(p string, d os.DirEntry, e error) error {
		if e == nil && !d.IsDir() {
			if s, e := d.Info(); e == nil {
				finalBytes += s.Size()
			}
		}
		return nil
	})
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"synthetic": true, "mode": *mode, "mixed": *attack, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "lines": *n, "input_bytes": st.Size(), "parsed": parsed, "seconds": elapsed.Seconds(), "requests_per_second": float64(parsed) / elapsed.Seconds(), "sample_interval_ms": 10, "peak_sampled_heap_bytes": peakHeap.Load(), "heap_sys_bytes": after.HeapSys, "allocated_bytes": after.TotalAlloc - before.TotalAlloc, "peak_sampled_spool_bytes": peakSpool.Load(), "spool_bytes": spool, "spool_limit_bytes": *capBytes, "final_artifact_bytes": finalBytes, "disk_upper_bound_bytes": finalBytes + spool, "complete": complete, "warnings": warnings, "evidence_complete": evidenceComplete})
}
