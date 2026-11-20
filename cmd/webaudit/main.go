package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"webaudit/audit"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, errout io.Writer) int {
	fs := flag.NewFlagSet("webaudit", flag.ContinueOnError)
	fs.SetOutput(errout)
	output := fs.String("o", "", "Write a new report file (default HTML; never overwrite)")
	format := fs.String("format", "", "html, json or csv (default console summary)")
	verbose := fs.Bool("verbose", false, "Show file-level diagnostics on stderr")
	version := fs.Bool("version", false, "Show version")
	help := fs.Bool("help", false, "Show help")
	var o audit.Options
	fs.StringVar(&o.LogRegex, "log-regex", "", "Explicit custom format with named groups ip,time,target,...")
	fs.IntVar(&o.MaxLineBytes, "max-line-bytes", 64*1024, "Maximum line size; oversized lines are skipped")
	fs.Int64Var(&o.MaxFileBytes, "max-file-bytes", 8<<30, "Maximum decompressed bytes per file")
	fs.IntVar(&o.MaxKeys, "max-keys", 4096, "Maximum retained keys per analysis table / dedup horizon")
	fs.IntVar(&o.MaxEvidenceBytes, "max-evidence-bytes", 32<<20, "Maximum retained incident evidence bytes")
	fs.IntVar(&o.MaxFindings, "max-findings", 2000, "Maximum retained incidents/signals")
	fs.Usage = func() {
		fmt.Fprintln(errout, "Usage: webaudit INPUT... [-o REPORT] [--format html|json|csv] [--verbose]\nInputs: files, gzip files, or directories. No output file without -o.")
		fs.PrintDefaults()
	}
	ordered, err := interspersed(args, fs)
	if err != nil {
		fmt.Fprintln(errout, err)
		return 2
	}
	if err = fs.Parse(ordered); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *version {
		fmt.Fprintf(out, "WebAudit %s (rules %s)\n", audit.Version, audit.RulesVersion)
		return 0
	}
	if *help {
		fs.Usage()
		return 0
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	if o.MaxEvidenceBytes < 512 || o.MaxEvidenceBytes > 1<<30 || o.MaxLineBytes < 64 || o.MaxLineBytes > 16<<20 || o.MaxFileBytes < 1 || o.MaxFileBytes > 1<<50 || o.MaxKeys < 1 || o.MaxKeys > 1000000 || o.MaxFindings < 1 || o.MaxFindings > 100000 {
		fmt.Fprintln(errout, "Invalid resource limits (see --help)")
		return 2
	}
	if *format != "" && *format != "html" && *format != "json" && *format != "csv" {
		fmt.Fprintln(errout, "--format must be html, json or csv")
		return 2
	}
	if o.LogRegex != "" {
		rx, er := regexp.Compile(o.LogRegex)
		if er != nil {
			fmt.Fprintln(errout, "Invalid --log-regex:", er)
			return 2
		}
		for _, name := range []string{"ip", "time", "target"} {
			if rx.SubexpIndex(name) < 0 {
				fmt.Fprintln(errout, "--log-regex requires named group", name)
				return 2
			}
		}
	}
	if *output != "" {
		if _, er := os.Lstat(*output); er == nil || !os.IsNotExist(er) {
			fmt.Fprintln(errout, "Output must be a new file; existing paths and input files are never overwritten")
			return 2
		}
	}
	r := audit.Analyze(fs.Args(), o)
	if *verbose {
		for _, f := range r.Files {
			fmt.Fprintf(errout, "%s: %d parsed, %d unparsed %s\n", audit.TerminalSafe(f.Path), f.Parsed, f.Unparsed, audit.TerminalSafe(f.Error))
		}
	}
	mode := *format
	if mode == "" {
		mode = "summary"
		if *output != "" {
			mode = "html"
		}
	}
	if *output != "" {
		f, er := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if er != nil {
			fmt.Fprintln(errout, er)
			return 2
		}
		er = audit.WriteReport(f, r, mode)
		closeErr := f.Close()
		if er != nil || closeErr != nil {
			fmt.Fprintln(errout, "Report write failed:", er, closeErr)
			return 1
		}
		if er = audit.WriteReport(out, r, "summary"); er != nil {
			fmt.Fprintln(errout, er)
			return 1
		}
		fmt.Fprintf(out, "\nReport: %s\n", audit.TerminalSafe(*output))
	} else if er := audit.WriteReport(out, r, mode); er != nil {
		fmt.Fprintln(errout, er)
		return 1
	}
	if r.Partial {
		return 1
	}
	return 0
}
func interspersed(args []string, fs *flag.FlagSet) ([]string, error) {
	var flags, paths []string
	for i := 0; i < len(args); i++ {
		s := args[i]
		if s == "--" {
			paths = append(paths, args[i+1:]...)
			break
		}
		if s == "-" || !strings.HasPrefix(s, "-") {
			paths = append(paths, s)
			continue
		}
		name := strings.TrimLeft(s, "-")
		if at := strings.IndexByte(name, '='); at >= 0 {
			name = name[:at]
		}
		f := fs.Lookup(name)
		if f == nil {
			if name == "h" {
				flags = append(flags, "--help")
				continue
			}
			return nil, fmt.Errorf("unknown flag %s", s)
		}
		flags = append(flags, s)
		boolean := false
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
			boolean = b.IsBoolFlag()
		}
		if !boolean && !strings.Contains(s, "=") {
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("missing value for %s", s)
			}
			flags = append(flags, args[i])
		}
	}
	return append(append(flags, "--"), paths...), nil
}
