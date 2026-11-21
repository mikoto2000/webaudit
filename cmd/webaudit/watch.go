package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"
	"webaudit/audit"
	"webaudit/internal/watch"
)

func runWatch(args []string, out, errout io.Writer) int {
	fs := flag.NewFlagSet("webaudit watch", flag.ContinueOnError)
	fs.SetOutput(errout)
	from := fs.String("from", "end", "beginning or end (saved checkpoint takes precedence)")
	include := fs.String("include", "", "Directory filename glob")
	exclude := fs.String("exclude", "", "Directory exclude glob")
	maxFiles := fs.Int("max-files", 64, "Maximum open files")
	maxLine := fs.Int("max-line-bytes", 64<<10, "Maximum partial line bytes")
	interval := fs.Duration("poll-interval", 250*time.Millisecond, "Polling interval")
	help := fs.Bool("help", false, "Show help")
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
	warn := func(s string) { fmt.Fprintln(errout, audit.TerminalSafe(s)) }
	r, e := watch.NewReader(fs.Args(), watch.ReaderOptions{Beginning: *from == "beginning", MaxFiles: *maxFiles, MaxLineBytes: *maxLine, Include: *include, Exclude: *exclude, Warn: warn})
	if e != nil {
		warn(e.Error())
		return 2
	}
	defer r.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	fmt.Fprintln(errout, "WebAudit Watch: monitoring", audit.TerminalSafe(fmt.Sprint(r.Targets)))
	for {
		e = r.Poll(ctx, func(l watch.Line) error {
			_, er := audit.Parse(l.Text, l.File, l.Number, "")
			if er != nil {
				warn("unparsed access log line")
			}
			return nil
		})
		if e != nil {
			if ctx.Err() != nil {
				return 0
			}
			warn(e.Error())
			return 1
		}
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
		}
	}
}
