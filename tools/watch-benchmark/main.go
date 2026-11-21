// watch-benchmark measures bounded monitor components without external services.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"
	"webaudit/audit"
	"webaudit/internal/watch"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--hook-child" {
		io.Copy(io.Discard, os.Stdin)
		time.Sleep(100 * time.Millisecond)
		return
	}
	mode := flag.String("mode", "engine", "engine, reader, idle, hooks, simulated, soak")
	lines := flag.Int("lines", 10000, "Events/lines")
	files := flag.Int("files", 32, "Reader files")
	duration := flag.Duration("duration", 10*time.Second, "Idle/soak duration")
	maxEvents := flag.Int("max-events", 8192, "Maximum retained events")
	geoEnabled := flag.Bool("geoip", false, "Enable local test MMDB")
	flag.Parse()
	start := time.Now()
	warnings := 0
	warn := func(string) { warnings++ }
	var geo *audit.GeoIP
	var err error
	if *geoEnabled {
		geo, err = audit.OpenGeoIP("audit/testdata/geoip/country.mmdb", "audit/testdata/geoip/asn.mmdb", "", 4096)
		must(err)
		defer geo.Close()
	}
	engine := watch.NewEngine(watch.EngineOptions{MaxEvents: *maxEvents, GeoIP: geo, Warn: warn})
	var processed, events, rotations int
	var peakHeap uint64
	sample := func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapAlloc > peakHeap {
			peakHeap = m.HeapAlloc
		}
	}
	switch *mode {
	case "engine", "simulated":
		now := time.Now().UTC().Truncate(5 * time.Minute)
		for i := 0; i < *lines; i++ {
			at := now
			if *mode == "simulated" {
				at = at.Add(time.Duration(i) * time.Second)
			}
			line := fmt.Sprintf("8.8.8.8 - - [%s] \"GET /.env HTTP/1.1\" 404 0", at.Format("02/Jan/2006:15:04:05 -0700"))
			v, e := audit.Parse(line, "access.log", int64(i+1), "")
			must(e)
			engine.Observe(v, at)
			processed++
			if i%256 == 255 {
				events += len(engine.Flush(at))
				sample()
			}
		}
		final := now
		if *mode == "simulated" {
			final = now.Add(time.Duration(*lines) * time.Second)
		}
		events += len(engine.Flush(final))
	case "reader", "idle", "soak":
		dir, e := os.MkdirTemp("", "webaudit-watch-benchmark-")
		must(e)
		defer os.RemoveAll(dir)
		paths := make([]string, *files)
		for i := range paths {
			paths[i] = filepath.Join(dir, fmt.Sprintf("site%d_access.log", i))
			must(os.WriteFile(paths[i], nil, 0600))
		}
		reader, e := watch.NewReader([]string{dir}, watch.ReaderOptions{Beginning: true, MaxFiles: *files + 16, Warn: warn})
		must(e)
		defer reader.Close()
		consume := func(l watch.Line) error {
			processed++
			if *mode == "soak" {
				v, er := audit.Parse(l.Text, l.File, l.Number, "")
				if er == nil {
					engine.Observe(v, time.Now())
				}
			}
			return nil
		}
		if *mode == "reader" {
			for i := 0; i < *lines; i++ {
				p := paths[i%len(paths)]
				f, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
				must(e)
				_, e = f.WriteString("line\n")
				must(e)
				must(f.Close())
				if i%1000 == 999 {
					must(reader.Poll(context.Background(), consume))
					p = paths[0]
					rot := p + fmt.Sprintf(".%d", i)
					must(os.Rename(p, rot))
					must(os.WriteFile(p, nil, 0600))
					rotations++
				}
			}
			must(reader.Poll(context.Background(), consume))
		} else {
			deadline := time.Now().Add(*duration)
			i := 0
			for time.Now().Before(deadline) {
				if *mode == "soak" {
					now := time.Now()
					for n := 0; n < 100; n++ {
						p := paths[(i+n)%len(paths)]
						f, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
						must(e)
						fmt.Fprintf(f, "8.8.8.8 - - [%s] \"GET /.env HTTP/1.1\" 404 0\n", now.Format("02/Jan/2006:15:04:05 -0700"))
						must(f.Close())
					}
					i += 100
					if i%1000 == 0 {
						p := paths[0]
						must(os.Rename(p, p+fmt.Sprintf(".%d", i)))
						must(os.WriteFile(p, nil, 0600))
						rotations++
					}
				}
				must(reader.Poll(context.Background(), consume))
				events += len(engine.Flush(time.Now()))
				sample()
				time.Sleep(250 * time.Millisecond)
			}
		}
	case "hooks":
		var completed, failed atomic.Int64
		d, e := watch.NewDispatcher(context.Background(), watch.HookOptions{Hooks: []watch.Hook{{Executable: os.Args[0], Args: []string{"--hook-child"}}}, Concurrency: 2, QueueSize: 8, Timeout: time.Second, Result: func(r watch.HookResult) {
			completed.Add(1)
			if r.Error != "" {
				failed.Add(1)
			}
		}}, nil)
		must(e)
		for i := 0; i < *lines; i++ {
			d.Dispatch(watch.IncidentEvent{IncidentID: fmt.Sprint(i), Revision: 1, EventType: "incident_created", Severity: "high", Notify: true})
		}
		time.Sleep(time.Second)
		d.Close()
		processed = *lines
		events = int(completed.Load())
		fmt.Fprintf(os.Stderr, "hook completed=%d failed=%d dropped=%d\n", completed.Load(), failed.Load(), d.Dropped())
	default:
		panic("unknown benchmark mode")
	}
	sample()
	elapsed := time.Since(start)
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": *mode, "os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(), "logical_cpus": runtime.NumCPU(), "geoip": *geoEnabled, "processed": processed, "incident_events_or_hook_completions": events, "rotations": rotations, "warnings": warnings, "elapsed_seconds": elapsed.Seconds(), "processed_per_second": float64(processed) / elapsed.Seconds(), "heap_after_gc_bytes": m.HeapAlloc, "sampled_peak_heap_bytes": peakHeap, "runtime_sys_bytes": m.Sys, "max_events": *maxEvents, "retained_records": len(engine.Records), "retained_incidents": len(engine.Incidents)})
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
