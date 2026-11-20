// Command benchmark generates synthetic logs and measures the full pipeline.
package main

import (
	"bufio"
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
		_, err = fmt.Fprintf(w, "192.0.2.%d - - [%s] \"GET /api/items/%d?nonce=%d HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0%s\"\n", i%16+1, start.Add(time.Duration(i/320)*time.Second).Format("02/Jan/2006:15:04:05 -0700"), i%32, i, pad)
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
	t := time.Now()
	r := audit.Analyze([]string{path}, audit.Options{})
	elapsed := time.Since(t)
	close(stop)
	<-done
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"synthetic": true, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "lines": *n, "bytes": st.Size(), "elapsed_seconds": elapsed.Seconds(), "requests_per_second": float64(r.Parsed) / elapsed.Seconds(), "peak_sampled_heap_bytes": peak.Load(), "heap_sys_bytes": mem.HeapSys, "total_alloc_bytes": mem.TotalAlloc, "parsed": r.Parsed, "unparsed": r.Unparsed, "duplicates": r.Duplicates, "incidents": len(r.Findings), "partial": r.Partial, "warnings": r.Warnings})
}
