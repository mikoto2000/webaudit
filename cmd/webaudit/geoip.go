package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
	"webaudit/audit"
	"webaudit/internal/geoipdb"
)

func runGeoIP(args []string, out, errout io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, "Usage: webaudit geoip download|update|status|rollback")
		return 0
	}
	if len(args) != 1 || (args[0] != "download" && args[0] != "update" && args[0] != "status" && args[0] != "rollback") {
		fmt.Fprintln(errout, "Usage: webaudit geoip download|update|status|rollback")
		return 2
	}
	dir, e := geoipdb.DefaultDir()
	if e != nil {
		fmt.Fprintln(errout, e)
		return 1
	}
	m := geoipdb.NewManager(dir)
	fmt.Fprintf(out, "WebAudit GeoIP %s\nDirectory: %s\n", args[0], audit.TerminalSafe(dir))
	switch args[0] {
	case "status":
		e := geoipdb.WithCurrent(dir, func(meta *geoipdb.Metadata) error { printGeoStatus(out, meta); return nil })
		if errors.Is(e, geoipdb.ErrNotInstalled) {
			fmt.Fprintln(out, "Not installed. Run: webaudit geoip download")
			return 0
		}
		if e != nil {
			fmt.Fprintln(errout, "Integrity: FAILED:", e)
			return 1
		}
		fmt.Fprintln(out, "Integrity: OK")
		return 0

	case "rollback":
		if e = m.Rollback(context.Background()); e != nil {
			fmt.Fprintln(errout, e)
			return 1
		}
		fmt.Fprintln(out, "Previous validated GeoIP generation restored.")
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r, e := m.Reconcile(ctx, args[0] == "update")
	if e != nil {
		fmt.Fprintln(errout, "GeoIP operation failed:", e)
		return 1
	}
	printGeoStatus(out, r.Metadata)
	if len(r.Changed) == 0 {
		if args[0] == "download" {
			fmt.Fprintln(out, "Already installed. Use 'webaudit geoip update' to check for updates.")
		} else {
			fmt.Fprintln(out, "No updates available.")
		}
	} else {
		for _, role := range r.Changed {
			fmt.Fprintf(out, "%s: downloaded, validated and activated\n", role)
		}
		fmt.Fprintln(out, "GeoIP databases ready.")
	}
	for _, w := range r.Warnings {
		fmt.Fprintln(errout, audit.TerminalSafe(w))
	}
	return 0
}
func printGeoStatus(w io.Writer, m *geoipdb.Metadata) {
	fmt.Fprintf(w, "Generation: %s\nLast update check: %s\n", audit.TerminalSafe(m.Current.ID), m.CheckedAt.Format(time.RFC3339))
	for _, d := range m.Current.Databases {
		build := "unknown"
		if d.BuildTime != nil {
			build = d.BuildTime.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "\n%s:\n  Provider: %s\n  Version: %s\n  Type: %s\n  Build: %s\n  Retrieved: %s\n  Size: %d bytes\n  SHA-256: %s\n  Source: %s\n", audit.TerminalSafe(d.Role), audit.TerminalSafe(d.Provider), audit.TerminalSafe(d.Version), audit.TerminalSafe(d.Type), build, d.DownloadedAt.Format(time.RFC3339), d.Size, audit.TerminalSafe(d.SHA256), audit.TerminalSafe(d.URL))
	}
	fmt.Fprintln(w, "\nIP Geolocation by DB-IP — https://db-ip.com — CC BY 4.0")
}
