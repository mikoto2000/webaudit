package audit

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BundleOptions contains explicit investigator metadata; missing values stay empty.
type BundleOptions struct {
	Warnings       []string `json:"-"`
	Title          string   `json:"title"`
	System         string   `json:"system"`
	Background     string   `json:"background"`
	Purpose        string   `json:"purpose"`
	Investigator   string   `json:"investigator"`
	Language       string   `json:"language"`
	MaxSpoolBytes  int64    `json:"max_spool_bytes"`
	MaxOutputBytes int64    `json:"max_output_bytes"`
}

func (o BundleOptions) defaults() BundleOptions {
	if o.Language == "" {
		o.Language = "ja"
	}
	if o.MaxSpoolBytes <= 0 {
		o.MaxSpoolBytes = 1 << 30
	}
	if o.MaxOutputBytes <= 0 {
		o.MaxOutputBytes = 1 << 30
	}
	return o
}

type LogInventory struct {
	CountQuality    string     `json:"count_quality"`
	ID              string     `json:"id"`
	Path            string     `json:"path"`
	Size            *int64     `json:"size_bytes"`
	SHA256          *string    `json:"sha256"`
	HashScope       string     `json:"hash_scope"`
	HashStatus      string     `json:"hash_status"`
	Compression     string     `json:"compression"`
	First           *time.Time `json:"first"`
	Last            *time.Time `json:"last"`
	TotalLines      int64      `json:"total_lines"`
	Parsed          int64      `json:"parsed"`
	Unparsed        int64      `json:"unparsed"`
	Excluded        int64      `json:"excluded"`
	Status          string     `json:"status"`
	Truncated       bool       `json:"truncated"`
	Changed         bool       `json:"changed_during_analysis"`
	DuplicateOf     string     `json:"duplicate_of,omitempty"`
	Formats         []string   `json:"formats"`
	LogTypes        []string   `json:"log_types"`
	AvailableFields []string   `json:"available_fields"`
	Error           string     `json:"error,omitempty"`
}

type InvestigationReport struct {
	Statistics          RequestStatistics    `json:"statistics"`
	EvidenceComplete    bool                 `json:"evidence_complete"`
	Evidence            EvidenceSummary      `json:"evidence"`
	Detections          []BundleDetection    `json:"detections"`
	FindingObservations []FindingObservation `json:"finding_observations"`
	AnalysisRules       []AnalysisRule       `json:"analysis_rules"`
	Coverage            []CoverageRow        `json:"coverage"`
	Schema              string               `json:"schema"`
	Metadata            BundleOptions        `json:"metadata"`
	Started             time.Time            `json:"started_at"`
	Finished            time.Time            `json:"finished_at"`
	Status              string               `json:"status"`
	Complete            bool                 `json:"complete"`
	CountQuality        string               `json:"count_quality"`
	Settings            map[string]any       `json:"settings"`
	Inventory           []LogInventory       `json:"inventory"`
	Analysis            Report               `json:"analysis"`
}
type BundleArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type BundleManifest struct {
	Schema            string            `json:"schema"`
	Version           string            `json:"version"`
	Build             map[string]string `json:"build"`
	Started           time.Time         `json:"started_at"`
	Finished          time.Time         `json:"finished_at"`
	Settings          map[string]any    `json:"settings"`
	RulesVersion      string            `json:"rules_version"`
	RulesSHA256       string            `json:"rules_sha256"`
	GeoIP             *GeoIPReport      `json:"geoip"`
	Inputs            []LogInventory    `json:"inputs"`
	Complete          bool              `json:"complete"`
	Warnings          []string          `json:"warnings"`
	Artifacts         []BundleArtifact  `json:"artifacts"`
	ArtifactHashScope string            `json:"artifact_hash_scope"`
}

func bundleSettings(o Options, b BundleOptions) map[string]any {
	mode := "auto"
	if o.LogRegex != "" {
		mode = "custom-regex"
	}
	var regexHash *string
	if o.LogRegex != "" {
		hash := sha256.Sum256([]byte(o.LogRegex))
		regexHash = ptr(hex.EncodeToString(hash[:]))
	}
	return map[string]any{"custom_regex_sha256": regexHash, "parser": mode, "custom_regex": "[not recorded]", "error_timezone": o.ErrorTimezone, "dedup_files": o.DeduplicateFiles, "max_line_bytes": o.MaxLineBytes, "max_file_bytes": o.MaxFileBytes, "max_keys": o.MaxKeys, "max_findings": o.MaxFindings, "max_evidence_bytes": o.MaxEvidenceBytes, "max_spool_bytes": b.MaxSpoolBytes, "max_output_bytes": b.MaxOutputBytes, "recorded_peer": "forwarded headers are not trusted", "language": b.Language}
}
func bundleID(prefix, value string) string {
	s := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(s[:16])
}
func rulesFingerprint() (string, error) {
	h := sha256.New()
	_, _ = h.Write(ruleData)
	err := fs.WalkDir(upstreamFiles, "upstream", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := upstreamFiles.ReadFile(p)
		if err != nil {
			return err
		}
		_, _ = h.Write([]byte(p + "\x00"))
		_, _ = h.Write(data)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)), err
}
func originalFingerprint(p string, limit int64) (*int64, *string, string, string) {
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, "unavailable", "unknown"
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, nil, "unavailable", "unknown"
	}
	size := st.Size()
	var magic [2]byte
	n, _ := f.Read(magic[:])
	compression := "none"
	if n == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		compression = "gzip"
	}
	if size > limit {
		return &size, nil, "size_limit", compression
	}
	if _, err = f.Seek(0, 0); err != nil {
		return &size, nil, "unavailable", compression
	}
	h := sha256.New()
	n64, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n64 > limit {
		return &size, nil, "unavailable", compression
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return &size, &sum, "complete", compression
}

type bundleWriter struct {
	dir         string
	limit, used int64
	files       []string
}
type bundleLimitWriter struct {
	b *bundleWriter
	w io.Writer
}

func (w bundleLimitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.b.limit-w.b.used {
		return 0, fmt.Errorf("report output byte limit reached")
	}
	n, err := w.w.Write(p)
	w.b.used += int64(n)
	return n, err
}
func (b *bundleWriter) write(name string, fn func(io.Writer) error) error {
	if filepath.IsAbs(name) || filepath.Clean(name) == ".." || strings.HasPrefix(filepath.Clean(name), ".."+string(filepath.Separator)) {
		return fmt.Errorf("invalid artifact path")
	}
	path := filepath.Join(b.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	b.files = append(b.files, name)
	err = fn(bundleLimitWriter{b, f})
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func (b *bundleWriter) json(name string, v any) error {
	return b.write(name, func(w io.Writer) error { e := json.NewEncoder(w); e.SetIndent("", "  "); return e.Encode(v) })
}
func (b *bundleWriter) csv(name string, header []string, rows func(func(...string) error) error) error {
	return b.write(name, func(w io.Writer) error {
		c := csv.NewWriter(w)
		write := func(row ...string) error {
			safe := make([]string, len(row))
			for i, v := range row {
				safe[i] = csvSafe(v)
			}
			return c.Write(safe)
		}
		if err := write(header...); err != nil {
			return err
		}
		if err := rows(write); err != nil {
			return err
		}
		c.Flush()
		return c.Error()
	})
}
func (b *bundleWriter) artifacts() ([]BundleArtifact, error) {
	names := append([]string(nil), b.files...)
	sort.Strings(names)
	out := make([]BundleArtifact, 0, len(names))
	for _, name := range names {
		f, err := os.Open(filepath.Join(b.dir, filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		out = append(out, BundleArtifact{name, hex.EncodeToString(h.Sum(nil)), n})
	}
	return out, nil
}

type bundleDiagnostic struct {
	File   string
	Line   int64
	Reason string
}
type bundleCapture struct {
	stats                *statisticsRecorder
	durationRegex        *regexp.Regexp
	spool                *requestSpool
	pendingSources       []string
	rules                []AnalysisRule
	aspects              []aspectDefinition
	observations         map[string]*ruleObservation
	aspectObservations   map[string]*ruleObservation
	signals              []Signal
	ready                map[string]bool
	o                    Options
	inputs               map[string]*LogInventory
	diagnostics          []bundleDiagnostic
	excluded             []bundleDiagnostic
	diagnosticsTruncated bool
}

func (c *bundleCapture) begin(p string) {
	if c == nil {
		return
	}
	size, hash, status, compression := originalFingerprint(p, c.o.MaxFileBytes)
	c.inputs[p] = &LogInventory{ID: bundleID("FILE-", p), Path: p, Size: size, SHA256: hash, HashScope: "original_file_bytes", HashStatus: status, Compression: compression, Status: "complete", CountQuality: "exact"}
}
func (c *bundleCapture) line(p string, n int64, kind, reason string) {
	if c == nil {
		return
	}
	in := c.inputs[p]
	in.TotalLines++
	switch kind {
	case "parsed":
		in.Parsed++
	case "excluded":
		in.Excluded++
		if len(c.excluded) < c.o.MaxKeys {
			c.excluded = append(c.excluded, bundleDiagnostic{p, n, reason})
		} else {
			c.diagnosticsTruncated = true
		}
	default:
		in.Unparsed++
		if len(c.diagnostics) < c.o.MaxKeys {
			c.diagnostics = append(c.diagnostics, bundleDiagnostic{p, n, reason})
		} else {
			c.diagnosticsTruncated = true
		}
	}
}
func (c *bundleCapture) event(e Event) {
	if c == nil {
		return
	}
	c.pendingSources = nil
	in := c.inputs[e.File]
	uniqueAppend(&in.LogTypes, e.LogType)
	format := "automatic supported parser"
	if c.o.LogRegex != "" {
		format = "custom-regex"
	}
	if e.format != "" {
		format = e.format
	}
	uniqueAppend(&in.Formats, format)
	if !e.TimezoneUnknown {
		if in.First == nil || e.Time.Before(*in.First) {
			in.First = ptr(e.Time)
		}
		if in.Last == nil || e.Time.After(*in.Last) {
			in.Last = ptr(e.Time)
		}
	}
	for name, ok := range map[string]bool{"source_ip": e.IP != "", "host": e.Host != nil, "method": e.Method != nil, "protocol": e.Protocol != nil, "request_uri": e.Target != "", "status": e.Status != nil, "response_bytes": e.Bytes != nil, "user_agent": e.UA != nil, "referer": e.Referer != nil, "timestamp": !e.TimezoneUnknown, "raw": true} {
		if ok {
			uniqueAppend(&in.AvailableFields, name)
		}
	}
}
func (c *bundleCapture) finish(p string, err error) {
	if c == nil {
		return
	}
	in := c.inputs[p]
	_, after, status, _ := originalFingerprint(p, c.o.MaxFileBytes)
	if in.SHA256 == nil || after == nil || *in.SHA256 != *after || status != "complete" {
		in.Changed = in.SHA256 != nil && after != nil && *in.SHA256 != *after
		in.Status = "partial"
		if in.SHA256 != nil {
			in.HashStatus = "verification_" + status
		}
		if in.Changed {
			in.HashStatus = "changed"
		}
		in.CountQuality = "lower_bound"
	}
	if err != nil {
		in.Error = err.Error()
		in.CountQuality = "lower_bound"
		in.Status = "partial"
		in.Truncated = strings.Contains(err.Error(), "limit reached")
		if in.Parsed == 0 {
			in.Status = "failed"
		}
	}
	if in.Unparsed > 0 {
		in.Status = "partial"
	}
	sort.Strings(in.AvailableFields)
	sort.Strings(in.LogTypes)
	sort.Strings(in.Formats)
}
func (c *bundleCapture) duplicate(p, old string) {
	if c == nil {
		return
	}
	in := c.inputs[p]
	if previous := c.inputs[old]; previous != nil {
		in.TotalLines = previous.TotalLines
		in.Excluded = previous.TotalLines
	}
	in.DuplicateOf = old
	in.Status = "excluded_duplicate"
	c.finish(p, nil)
}

// GenerateBundle writes only into an exclusively created directory. Legacy outputs
// and source logs are never modified. Failed output retains an INCOMPLETE marker.
func GenerateBundle(paths []string, target string, o Options, b BundleOptions) (result *InvestigationReport, err error) {
	o = o.defaults()
	b = b.defaults()
	if b.Language != "ja" && b.Language != "en" {
		return nil, fmt.Errorf("--lang must be ja or en")
	}
	if len(paths) > o.MaxKeys {
		return nil, fmt.Errorf("explicit input path limit exceeded (max-keys)")
	}
	if o.LogRegex != "" {
		rx, compileErr := regexp.Compile(o.LogRegex)
		if compileErr != nil {
			return nil, fmt.Errorf("invalid custom regex; pattern not recorded")
		}
		for _, name := range []string{"ip", "time", "target"} {
			if rx.SubexpIndex(name) < 0 {
				return nil, fmt.Errorf("custom regex requires named group %s", name)
			}
		}
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(target); !os.IsNotExist(err) {
		return nil, fmt.Errorf("report directory must be new")
	}
	// Reserve the final directory with mkdir (exclusive on all supported OSes).
	// An incomplete marker remains on failure; no existing directory is replaced.
	if err = os.Mkdir(target, 0700); err != nil {
		return nil, err
	}
	marker, err := os.OpenFile(filepath.Join(target, "INCOMPLETE"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if _, err = io.WriteString(marker, "Report generation is incomplete. Do not treat these artifacts as a completed report.\n"); err != nil {
		_ = marker.Close()
		return nil, err
	}
	if err = marker.Close(); err != nil {
		return nil, err
	}
	writer := &bundleWriter{dir: target, limit: b.MaxOutputBytes}
	c := &bundleCapture{o: o, inputs: map[string]*LogInventory{}, rules: analysisRules()}
	spool, err := newRequestSpool(target, b.MaxSpoolBytes)
	if err != nil {
		return nil, err
	}
	c.spool = spool
	defer spool.remove()
	c.initStatistics()
	o.bundle = c
	o.RetainUpstreamEvidence = true
	started := o.Now().UTC()
	analysis := Analyze(paths, o)
	for _, warning := range b.Warnings {
		analysis.AddWarning(warning)
	}
	r := &InvestigationReport{Schema: "webaudit/investigation-1", Metadata: b, Started: started, Finished: o.Now().UTC(), Settings: bundleSettings(o, b), Analysis: analysis, Complete: !analysis.Partial, CountQuality: "exact", Status: "completed"}
	for _, in := range analysis.Files {
		row := c.inputs[in.Path]
		if row == nil {
			c.begin(in.Path)
			row = c.inputs[in.Path]
			row.Status = "failed"
			row.CountQuality = "unavailable"
			row.Error = in.Error
			r.Complete = false
		}
		if row.Status == "partial" || row.Status == "failed" {
			r.Complete = false
		}
		r.Inventory = append(r.Inventory, *row)
	}
	if c.diagnosticsTruncated {
		r.Complete = false
		r.Analysis.warn("Report diagnostic limit reached; diagnostic samples are incomplete")
	}
	if !r.Complete {
		r.Analysis.Partial = true
		r.Analysis.warn("Investigation report is incomplete; inspect inventory and diagnostic completeness")
		r.Status = "partial"
		r.CountQuality = "lower_bound"
	}
	if analysis.Parsed == 0 && analysis.Partial {
		r.Status = "failed"
	}
	c.stats.finalizeTimeline()
	buildCoverage(r, c)
	if err = exportRequestEvidence(writer, r, c); err != nil {
		return nil, err
	}
	r.Statistics = c.stats.model(r)
	if c.stats.truncated {
		r.Complete = false
		if r.Status != "failed" {
			r.Status = "partial"
		}
		r.Analysis.Partial = true
		r.Analysis.warn("Statistics detail limit reached; inspect other buckets, unique-IP quality and truncated labels")
	}
	if err = writeStatistics(writer, r); err != nil {
		return nil, err
	}
	if err = os.Remove(spool.path); err != nil {
		return nil, err
	}
	if err = writeCoverage(writer, r); err != nil {
		return nil, err
	}
	if err = writer.csv("log-inventory.csv", []string{"file_id", "path", "size_bytes", "sha256", "hash_scope", "compression", "first", "last", "total_lines", "parsed", "unparsed", "excluded", "status", "truncated", "changed", "error"}, func(write func(...string) error) error {
		for _, in := range r.Inventory {
			size, hash := "", ""
			if in.Size != nil {
				size = strconv.FormatInt(*in.Size, 10)
			}
			if in.SHA256 != nil {
				hash = *in.SHA256
			}
			if err := write(in.ID, in.Path, size, hash, in.HashScope, in.Compression, bundleTime(in.First), bundleTime(in.Last), strconv.FormatInt(in.TotalLines, 10), strconv.FormatInt(in.Parsed, 10), strconv.FormatInt(in.Unparsed, 10), strconv.FormatInt(in.Excluded, 10), in.Status, strconv.FormatBool(in.Truncated), strconv.FormatBool(in.Changed), in.Error); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	for _, item := range []struct {
		name string
		rows []bundleDiagnostic
	}{{"parse-errors", c.diagnostics}, {"excluded-requests", c.excluded}} {
		if err = writer.csv("diagnostics/"+item.name+".csv", []string{"file_id", "source_file", "source_line", "reason", "sample_complete"}, func(write func(...string) error) error {
			for _, d := range item.rows {
				if err := write(bundleID("FILE-", d.File), d.File, strconv.FormatInt(d.Line, 10), d.Reason, strconv.FormatBool(!c.diagnosticsTruncated)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if err = writer.write("diagnostics/execution-log.txt", func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "WebAudit %s\nStarted: %s\nFinished: %s\nStatus: %s\n", Version, started.Format(time.RFC3339Nano), r.Finished.Format(time.RFC3339Nano), r.Status)
		for _, warning := range r.Analysis.Warnings {
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(w, TerminalSafe(warning))
		}
		return err
	}); err != nil {
		return nil, err
	}
	if err = writer.json("report.json", r); err != nil {
		return nil, err
	}
	if err = writer.write("report.html", func(w io.Writer) error { return WriteReportWithLanguage(w, r.Analysis, "html", b.Language) }); err != nil {
		return nil, err
	}
	artifacts, err := writer.artifacts()
	if err != nil {
		return nil, err
	}
	rulesHash, err := rulesFingerprint()
	if err != nil {
		return nil, err
	}
	build := map[string]string{"go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" || s.Key == "vcs.modified" {
				build[s.Key] = s.Value
			}
		}
	}
	manifest := BundleManifest{Schema: "webaudit/manifest-1", Version: Version, Build: build, Started: r.Started, Finished: r.Finished, Settings: r.Settings, RulesVersion: RulesVersion, RulesSHA256: rulesHash, GeoIP: r.Analysis.GeoIP, Inputs: r.Inventory, Complete: r.Complete, Warnings: r.Analysis.Warnings, Artifacts: artifacts, ArtifactHashScope: "all listed artifacts; manifest excludes its own hash"}
	if err = writer.json("manifest.json", manifest); err != nil {
		return nil, err
	}
	if err = os.Remove(filepath.Join(target, "INCOMPLETE")); err != nil {
		return nil, err
	}
	return r, nil
}
func bundleTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}
