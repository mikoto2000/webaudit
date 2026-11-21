package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"webaudit/audit"
	"webaudit/internal/geoipdb"
	"webaudit/internal/watch"
)

func runWatch(args []string, out, errout io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runWatchContext(ctx, args, out, errout)
}

func runWatchContext(ctx context.Context, args []string, out, errout io.Writer) int {
	fs := flag.NewFlagSet("webaudit watch", flag.ContinueOnError)
	fs.SetOutput(errout)
	from := fs.String("from", "end", "beginning or end (saved checkpoint takes precedence)")
	include := fs.String("include", "", "Directory filename glob")
	exclude := fs.String("exclude", "", "Directory exclude glob")
	maxFiles := fs.Int("max-files", 64, "Maximum open files")
	maxLine := fs.Int("max-line-bytes", 64<<10, "Maximum partial line bytes")
	interval := fs.Duration("poll-interval", 250*time.Millisecond, "Polling interval")
	help := fs.Bool("help", false, "Show help")
	format := fs.String("format", "text", "text or jsonl")
	lateness := fs.Duration("allowed-lateness", 30*time.Second, "Maximum out-of-order event delay")
	retention := fs.Duration("retention", 15*time.Minute, "Detection retention horizon")
	maxEvents := fs.Int("max-events", 8192, "Maximum retained normalized events")
	noState := fs.Bool("no-state", false, "Disable all checkpoint persistence")
	resetState := fs.Bool("reset-state", false, "Ignore saved checkpoint and start from --from")
	var hooks []watch.Hook
	fs.Func("on-detect", "Hook executable path; repeat for multiple hooks", func(s string) error {
		if len(hooks) >= 16 {
			return fmt.Errorf("maximum 16 hooks")
		}
		hooks = append(hooks, watch.Hook{Executable: s})
		return nil
	})
	fs.Func("on-detect-arg", "Literal argument for preceding --on-detect", func(s string) error {
		if len(hooks) == 0 {
			return fmt.Errorf("requires preceding --on-detect")
		}
		h := &hooks[len(hooks)-1]
		if len(h.Args) >= 64 {
			return fmt.Errorf("maximum 64 hook arguments")
		}
		h.Args = append(h.Args, s)
		return nil
	})
	severity := fs.String("on-detect-severity", "high", "Minimum hook severity: low, medium, high, critical")
	events := fs.String("on-detect-event", "created", "Hook events: created, updated, all (significant changes only)")
	hookTimeout := fs.Duration("hook-timeout", 10*time.Second, "Timeout per hook")
	hookConcurrency := fs.Int("hook-concurrency", 1, "Concurrent hooks (1..32)")
	hookQueue := fs.Int("hook-queue-size", 128, "Maximum queued hook notifications")
	country := fs.String("geoip-country", "", "Local Country MMDB override")
	asn := fs.String("geoip-asn", "", "Local ASN MMDB override")
	fs.Usage = func() {
		fmt.Fprintln(errout, "Usage: webaudit watch INPUT... [--from beginning|end]")
		fs.PrintDefaults()
	}
	ordered, e := interspersed(args, fs)
	if e != nil {
		fmt.Fprintln(errout, e)
		return 2
	}
	if e = fs.Parse(ordered); e != nil {
		if e == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *help {
		fs.Usage()
		return 0
	}
	if (*from != "end" && *from != "beginning") || *interval < 10*time.Millisecond || *interval > time.Minute {
		fmt.Fprintln(errout, "invalid watch options")
		return 2
	}
	if (*format != "text" && *format != "jsonl") || *lateness < time.Nanosecond || *lateness > time.Hour || *retention < 5*time.Minute+*lateness || *retention > 24*time.Hour || *maxEvents < 1 || *maxEvents > 100000 {
		fmt.Fprintln(errout, "invalid watch detection options")
		return 2
	}
	var diagnosticMu sync.Mutex
	diagnosticWindow := time.Now()
	diagnosticCount := 0
	diagnosticSeen := map[string]bool{}
	suppressed := uint64(0)
	warn := func(s string) {
		diagnosticMu.Lock()
		defer diagnosticMu.Unlock()
		if time.Since(diagnosticWindow) >= 5*time.Second {
			if suppressed > 0 {
				fmt.Fprintf(errout, "%d repeated/excess diagnostics suppressed\n", suppressed)
			}
			diagnosticWindow = time.Now()
			diagnosticCount = 0
			clear(diagnosticSeen)
			suppressed = 0
		}
		if diagnosticCount >= 10 || diagnosticSeen[s] {
			suppressed++
			return
		}
		diagnosticCount++
		diagnosticSeen[s] = true
		fmt.Fprintln(errout, audit.TerminalSafe(s))
	}
	defer func() {
		diagnosticMu.Lock()
		defer diagnosticMu.Unlock()
		if suppressed > 0 {
			fmt.Fprintf(errout, "%d repeated/excess diagnostics suppressed\n", suppressed)
		}
	}()
	executable, er := os.Executable()
	if er != nil {
		warn(er.Error())
		return 2
	}
	geoDir, pathErr := geoipdb.DefaultDir()
	if pathErr != nil {
		warn(pathErr.Error())
	}
	geo, warnings, er := audit.OpenManagedGeoIP(*country, *asn, geoDir, filepath.Join(filepath.Dir(executable), "geoip"), 4096)
	if er != nil {
		warn(er.Error())
		return 2
	}
	defer geo.Close()
	for _, w := range warnings {
		warn(w)
	}
	r, e := watch.NewReader(fs.Args(), watch.ReaderOptions{Beginning: *from == "beginning", MaxFiles: *maxFiles, MaxLineBytes: *maxLine, Include: *include, Exclude: *exclude, Warn: warn})
	if e != nil {
		warn(e.Error())
		return 2
	}
	defer r.Close()
	engine := watch.NewEngine(watch.EngineOptions{AllowedLateness: *lateness, Retention: *retention, MaxEvents: *maxEvents, Warn: warn, GeoIP: geo})
	var store *watch.Store
	var history map[string]uint64
	if !*noState {
		key := fmt.Sprintf("%s/%s/%s/%d/%d/%s/%s", audit.RulesVersion, *lateness, *retention, *maxEvents, *maxLine, *include, *exclude)
		store, e = watch.OpenStore(r.Targets, key, *resetState)
		if e != nil {
			warn(e.Error())
			return 2
		}
		defer store.Close()
		state, er := store.Load()
		if er != nil {
			warn(er.Error())
			return 2
		}
		if er = watch.Restore(r, engine, state); er != nil {
			warn(er.Error())
			return 2
		}
		if state != nil {
			history = state.Notifications
		}
	}
	dispatcher, e := watch.NewDispatcher(ctx, watch.HookOptions{Hooks: hooks, Severity: *severity, Events: *events, Timeout: *hookTimeout, Concurrency: *hookConcurrency, QueueSize: *hookQueue, Warn: warn}, history)
	if e != nil {
		warn(e.Error())
		return 2
	}
	defer dispatcher.Close()
	defer func() {
		if dropped := dispatcher.Dropped(); dropped > 0 {
			warn(fmt.Sprintf("hook notifications dropped: %d", dropped))
		}
	}()
	save := func() error {
		if store != nil {
			return store.Save(watch.Capture(r, engine, dispatcher.History()))
		}
		return nil
	}
	lastSave := time.Now()
	encode := json.NewEncoder(out)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	fmt.Fprintln(errout, "WebAudit Watch: monitoring", audit.TerminalSafe(fmt.Sprint(r.Targets)))
	for {
		e = r.Poll(ctx, func(l watch.Line) error {
			v, er := audit.Parse(l.Text, l.File, l.Number, "")
			if er != nil {
				warn("unparsed access log line")
			} else {
				engine.Observe(v, time.Now())
			}
			return nil
		})
		if e != nil {
			if ctx.Err() != nil {
				if er := save(); er != nil {
					warn(er.Error())
					return 1
				}
				return 0
			}
			warn(e.Error())
			return 1
		}
		for _, v := range engine.Flush(time.Now()) {
			if *format == "jsonl" {
				e = encode.Encode(v)
			} else {
				_, e = fmt.Fprintf(out, "[%s] %s %s %s revision=%d IP=%s outcome=%s count=%d\n", v.UpdatedAt.Format("15:04:05"), v.EventType, v.Severity, v.IncidentID, v.Revision, strings.Join(v.SourceIPs, ","), v.Outcome, v.Count)
			}
			if e != nil {
				warn(e.Error())
				return 1
			}
			dispatcher.Dispatch(v)
		}
		dispatcher.Prune(engine.Incidents)
		if time.Since(lastSave) >= time.Second {
			if er := save(); er != nil {
				warn(er.Error())
				return 1
			}
			lastSave = time.Now()
		}
		select {
		case <-ctx.Done():
			if er := save(); er != nil {
				warn(er.Error())
				return 1
			}
			return 0
		case <-ticker.C:
		}
	}
}
