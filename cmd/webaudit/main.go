package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"webaudit/audit"
	"webaudit/internal/geoipdb"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, errout io.Writer) int {
	if len(args) > 0 && args[0] == "watch" {
		return runWatch(args[1:], out, errout)
	}
	if len(args) > 0 && args[0] == "geoip" {
		return runGeoIP(args[1:], out, errout)
	}
	fs := flag.NewFlagSet("webaudit", flag.ContinueOnError)
	fs.SetOutput(errout)
	output := fs.String("o", "", "Write a new report file (default HTML; never overwrite)")
	var bundle audit.BundleOptions
	fs.BoolVar(&bundle.IncludeSensitiveEvidence, "include-sensitive-evidence", false, "Bundle only: include unmasked sensitive source values (review before sharing)")
	reportDir := fs.String("report-dir", "", "Create a new investigation report directory (exclusive; batch only)")
	fs.StringVar(&bundle.Title, "report-title", "", "Optional investigation report title")
	fs.StringVar(&bundle.System, "system-name", "", "Optional target system name")
	fs.StringVar(&bundle.Background, "investigation-background", "", "Optional investigation background")
	fs.StringVar(&bundle.Purpose, "investigation-purpose", "", "Optional investigation purpose")
	fs.StringVar(&bundle.Investigator, "investigator", "", "Optional investigator name")
	fs.Int64Var(&bundle.MaxSpoolBytes, "max-spool-bytes", 1<<30, "Maximum private report spool bytes")
	fs.Int64Var(&bundle.MaxOutputBytes, "max-report-bytes", 1<<30, "Maximum total report artifact bytes")
	format := fs.String("format", "", "html, json or csv (default console summary)")
	language := fs.String("lang", "ja", "Report language: ja or en (default ja; legacy JSON/CSV unchanged)")
	verbose := fs.Bool("verbose", false, "Show input progress and file-level diagnostics on stderr")
	version := fs.Bool("version", false, "Show version")
	help := fs.Bool("help", false, "Show help")
	var o audit.Options
	country := fs.String("geoip-country", "", "Local Country MMDB (overrides executable geoip/ discovery)")
	asn := fs.String("geoip-asn", "", "Local ASN MMDB (overrides executable geoip/ discovery)")
	fs.StringVar(&o.ErrorTimezone, "error-timezone", "", "Explicit IANA timezone for timezone-free error logs (for example Asia/Tokyo)")
	fs.BoolVar(&o.DeduplicateFiles, "dedup-files", false, "Opt-in: exclude byte-identical complete input files; retain repeated requests")
	fs.StringVar(&o.LogRegex, "log-regex", "", "Explicit custom format with named groups ip,time,target,...")
	fs.IntVar(&o.MaxLineBytes, "max-line-bytes", 64*1024, "Maximum line size; oversized lines are skipped")
	fs.Int64Var(&o.MaxFileBytes, "max-file-bytes", 8<<30, "Maximum decompressed bytes per file")
	fs.IntVar(&o.MaxKeys, "max-keys", 4096, "Maximum retained keys per analysis table")
	fs.IntVar(&o.MaxEvidenceBytes, "max-evidence-bytes", 32<<20, "Maximum retained incident evidence bytes")
	fs.IntVar(&o.MaxFindings, "max-findings", 2000, "Maximum incidents, signals and source alerts per collection")
	fs.Usage = func() {
		fmt.Fprintln(errout, "Usage: webaudit INPUT... [-o REPORT] [--format html|json|csv] [--lang ja|en] [--verbose]\nInputs: files, gzip files, or directories. No output file without -o.\nInvestigation bundle: webaudit INPUT... --report-dir NEW_DIRECTORY [--lang ja|en]\nRealtime monitoring: webaudit watch INPUT... [--help]\nGeoIP management: webaudit geoip download|update|status|rollback")
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
	if *language != "ja" && *language != "en" {
		fmt.Fprintln(errout, "--lang must be ja or en")
		return 2
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
	if *reportDir != "" && (*output != "" || *format != "") {
		fmt.Fprintln(errout, "--report-dir cannot be combined with -o or --format")
		return 2
	}
	if bundle.MaxSpoolBytes < 1 || bundle.MaxSpoolBytes > 1<<50 || bundle.MaxOutputBytes < 1 || bundle.MaxOutputBytes > 1<<50 {
		fmt.Fprintln(errout, "Invalid report resource limits")
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
	if o.ErrorTimezone != "" {
		if _, err := time.LoadLocation(o.ErrorTimezone); err != nil {
			fmt.Fprintln(errout, "Invalid --error-timezone:", err)
			return 2
		}
	}
	if *output != "" {
		if _, er := os.Lstat(*output); er == nil || !os.IsNotExist(er) {
			fmt.Fprintln(errout, "Output must be a new file; existing paths and input files are never overwritten")
			return 2
		}
	}
	executable, er := os.Executable()
	if er != nil {
		fmt.Fprintln(errout, er)
		return 2
	}
	geoDir, pathErr := geoipdb.DefaultDir()
	var geoWarnings []string
	if pathErr != nil && (*country == "" || *asn == "") {
		geoWarnings = append(geoWarnings, pathErr.Error())
	}
	geo, warnings, er := audit.OpenManagedGeoIP(*country, *asn, geoDir, filepath.Join(filepath.Dir(executable), "geoip"), o.MaxKeys)
	geoWarnings = append(geoWarnings, warnings...)
	if er != nil {
		fmt.Fprintln(errout, er)
		return 2
	}
	defer geo.Close()
	o.GeoIP = geo
	if *verbose {
		o.Progress = newInputProgress(errout)
	}
	if *reportDir != "" {
		bundle.Language = *language
		bundle.Warnings = geoWarnings
		report, err := audit.GenerateBundle(fs.Args(), *reportDir, o, bundle)
		if err != nil {
			fmt.Fprintln(errout, audit.TerminalSafe(err.Error()))
			return 1
		}
		if err = audit.WriteReport(out, report.Analysis, "summary"); err != nil {
			fmt.Fprintln(errout, audit.TerminalSafe(err.Error()))
			return 1
		}
		fmt.Fprintln(out, "\nReport directory:", audit.TerminalSafe(*reportDir))
		if !report.Complete {
			return 1
		}
		return 0
	}
	mode := *format
	if mode == "" {
		mode = "summary"
		if *output != "" {
			mode = "html"
		}
	}
	o.RetainUpstreamEvidence = mode == "html"
	r := audit.Analyze(fs.Args(), o)
	for _, w := range geoWarnings {
		r.AddWarning(w)
		fmt.Fprintln(errout, audit.TerminalSafe(w))
	}
	if *verbose {
		for _, f := range r.Files {
			fmt.Fprintf(errout, "%s: %d parsed, %d unparsed %s\n", audit.TerminalSafe(f.Path), f.Parsed, f.Unparsed, audit.TerminalSafe(f.Error))
		}
	}
	if *output != "" {
		if er := os.MkdirAll(filepath.Dir(*output), 0700); er != nil {
			fmt.Fprintln(errout, er)
			return 2
		}
		f, er := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if er != nil {
			fmt.Fprintln(errout, er)
			return 2
		}
		if er = writeAndCloseReport(f, func(w io.Writer) error { return audit.WriteReportWithLanguage(w, r, mode, *language) }); er != nil {
			fmt.Fprintln(errout, "Report write failed:", er)
			return 1
		}
		if er = audit.WriteReport(out, r, "summary"); er != nil {
			fmt.Fprintln(errout, er)
			return 1
		}
		fmt.Fprintf(out, "\nReport: %s\n", audit.TerminalSafe(*output))
	} else if er := audit.WriteReportWithLanguage(out, r, mode, *language); er != nil {
		fmt.Fprintln(errout, er)
		return 1
	}
	if r.Partial {
		return 1
	}
	return 0
}

// f must be a newly created, exclusive output file. A summary failure after this
// succeeds must not delete the completed report.
func writeAndCloseReport(f *os.File, write func(io.Writer) error) error {
	writeErr := write(f)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		if removeErr := os.Remove(f.Name()); removeErr != nil {
			return errors.Join(err, fmt.Errorf("remove incomplete report: %w", removeErr))
		}
		return err
	}
	return nil
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
