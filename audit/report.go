package audit

import (
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"unicode"
)

//go:embed report.html
var htmlSource string
var htmlReport = template.Must(template.New("report").Parse(htmlSource))

func WriteReport(w io.Writer, r Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "html":
		return htmlReport.Execute(w, r)
	case "csv":
		return writeCSV(w, r)
	case "summary":
		var b strings.Builder
		if err := writeSummary(&b, r); err != nil {
			return err
		}
		_, err := io.WriteString(w, b.String())
		return err
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}
func TerminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == 0x202e || r == 0x202d || r >= 0x2066 && r <= 0x2069 {
			return '�'
		}
		return r
	}, s)
}
func writeSummary(w io.Writer, r Report) error {
	state := "completed"
	if r.Partial {
		state = "partial (coverage limits or input errors)"
	}
	fmt.Fprintf(w, "WebAudit %s - Analysis %s\n\nAnalyzed:\n  Files: %d\n  Requests: %d\n  Unparsed: %d\n  Duplicate observations excluded: %d\n", r.Version, state, len(r.Files), r.Parsed, r.Unparsed, r.Duplicates)
	if r.First != nil && r.Last != nil {
		fmt.Fprintf(w, "  Period: %s .. %s\n", r.First.Format("2006-01-02T15:04:05Z07:00"), r.Last.Format("2006-01-02T15:04:05Z07:00"))
	}
	fmt.Fprintf(w, "\nFindings: %d\n", len(r.Findings))
	for _, s := range []string{"confirmed_success", "possible_success", "unknown", "likely_failed", "confirmed_failure"} {
		fmt.Fprintf(w, "  %-20s %d\n", s, r.Outcomes[s])
	}
	fmt.Fprintln(w, "\nTop findings:")
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  No WebAudit incidents; review upstream detections and coverage below.")
	}
	for i, f := range r.Findings {
		if i == 5 {
			break
		}
		desc := "Review candidate"
		if len(f.Rules) > 0 {
			desc = f.Rules[0].Description
		}
		fmt.Fprintf(w, "  %-8s %s | %s | %s | %d observations\n", strings.ToUpper(f.Severity), TerminalSafe(desc), TerminalSafe(f.IP), f.Outcome.Verdict, f.Count)
	}
	fmt.Fprintf(w, "\nUpstream detections:\n  Hub alerts: %d\n  Aura signature groups: %d\n  Aura analysis findings: %d\n", len(r.UpstreamAlerts), len(r.AuraMatches), len(r.AuraAnalysis))
	for i, a := range r.UpstreamAlerts {
		if i == 5 {
			break
		}
		fmt.Fprintf(w, "  %s | %s | %d events\n", TerminalSafe(a.RuleID), TerminalSafe(a.IP), a.Count)
	}
	if r.GeoIP != nil {
		writeGeoSummary(w, r.GeoIP)
	}
	fmt.Fprintln(w, "\nWarnings:")
	for _, s := range r.Warnings {
		fmt.Fprintln(w, "  "+TerminalSafe(s))
	}
	return nil
}
func csvSafe(s string) string {
	trim := strings.TrimLeftFunc(s, unicode.IsSpace)
	if trim != "" && strings.ContainsRune("=+-@", rune(trim[0])) {
		return "'" + s
	}
	if len(s) > 0 && strings.ContainsRune("\t\r\n", rune(s[0])) {
		return "'" + s
	}
	return s
}
func writeCSV(w io.Writer, r Report) error {
	c := csv.NewWriter(w)
	write := func(row []string) error {
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		return c.Write(row)
	}
	if err := write([]string{"record_type", "id", "severity", "verdict", "ip", "observations", "reasons", "evidence_json", "details_json"}); err != nil {
		return err
	}
	meta := r
	meta.Findings = nil
	meta.UpstreamAlerts = nil
	meta.AuraMatches = nil
	meta.AuraAnalysis = nil
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err = write([]string{"metadata", "", "", "", "", "", "", "", string(b)}); err != nil {
		return err
	}
	for _, f := range r.Findings {
		e, err := json.Marshal(f.Evidence)
		if err != nil {
			return err
		}
		details, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if err = write([]string{"incident", f.ID, f.Severity, f.Outcome.Verdict, f.IP, strconv.FormatInt(f.Count, 10), strings.Join(f.Outcome.Reasons, "; "), string(e), string(details)}); err != nil {
			return err
		}
	}
	for _, group := range [][]SourceAlert{r.UpstreamAlerts, r.AuraMatches, r.AuraAnalysis} {
		for _, a := range group {
			details, err := json.Marshal(a)
			if err != nil {
				return err
			}
			if err = write([]string{a.Source, a.RuleID, "", "unknown", a.IP, strconv.FormatInt(a.Count, 10), "Source detection; outcome not established", "", string(details)}); err != nil {
				return err
			}
		}
	}
	c.Flush()
	return c.Error()
}

func writeGeoSummary(w io.Writer, g *GeoIPReport) {
	fmt.Fprintln(w, "\nGeoIP / ASN (investigation context):")
	for _, d := range g.Databases {
		date := "unknown"
		if d.UpdatedAt != nil {
			date = *d.UpdatedAt
		}
		fmt.Fprintf(w, "  %s | %s | %s | updated %s | %s\n", TerminalSafe(d.Provider), TerminalSafe(d.File), TerminalSafe(d.Type), date, TerminalSafe(d.License))
	}
	fmt.Fprintln(w, "  "+g.Context)
	for _, set := range []struct {
		name string
		rows []GeoGroup
	}{{"Country", g.Countries}, {"ASN", g.ASNs}} {
		for i, x := range set.rows {
			if i == 5 {
				break
			}
			fmt.Fprintf(w, "  %s %s (%s): %d requests, %d incidents, multiple suspicious IPs: %t; %s\n", set.name, TerminalSafe(x.Key), TerminalSafe(x.Name), x.Requests, x.Incidents, x.MultiIP, TerminalSafe(strings.Join(x.IPs, ", ")))
		}
	}
	for i, p := range g.Peers {
		if i == 5 {
			break
		}
		ck, cn, ak, an := geoKeys(p.Info)
		fmt.Fprintf(w, "  Peer %s: %s | %s %s | ASN %s %s\n", TerminalSafe(p.IP), p.Info.Classification, TerminalSafe(ck), TerminalSafe(cn), TerminalSafe(ak), TerminalSafe(an))
	}
}
