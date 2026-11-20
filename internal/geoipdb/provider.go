package geoipdb

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Release struct{ Role, Version, URL, SHA1 string }
type Source interface {
	Latest(context.Context, string) (Release, error)
	Fetch(context.Context, Release, io.Writer) error
}
type Provider struct {
	client               *http.Client
	maxPage, maxDownload int64
}

var downloadPath = regexp.MustCompile(`^/free/dbip-(country|asn)-lite-([0-9]{4}-(?:0[1-9]|1[0-2]))\.mmdb\.gz$`)

func allowedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("GeoIP requires official HTTPS URL: %q", raw)
	}
	switch u.Host {
	case "db-ip.com":
		if u.Path == "/db/download/ip-to-country-lite" || u.Path == "/db/download/ip-to-asn-lite" {
			return nil
		}
	case "download.db-ip.com":
		if downloadPath.MatchString(u.Path) {
			return nil
		}
	}
	return fmt.Errorf("GeoIP URL is outside the official allowlist: %q", raw)
}
func NewProvider() *Provider {
	return &Provider{client: &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 10 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many GeoIP redirects")
		}
		return allowedURL(r.URL.String())
	}}, maxPage: 1 << 20, maxDownload: 64 << 20}
}
func (p *Provider) get(ctx context.Context, raw string) (io.ReadCloser, error) {
	if err := allowedURL(raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WebAudit GeoIP manager; +https://github.com/mikoto2000/webaudit)")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GeoIP download %s: HTTP %d", raw, resp.StatusCode)
	}
	return resp.Body, nil
}
func (p *Provider) Latest(ctx context.Context, role string) (Release, error) {
	if role != "country" && role != "asn" {
		return Release{}, fmt.Errorf("unknown GeoIP role %q", role)
	}
	body, err := p.get(ctx, "https://db-ip.com/db/download/ip-to-"+role+"-lite")
	if err != nil {
		return Release{}, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, p.maxPage+1))
	if err != nil {
		return Release{}, err
	}
	if int64(len(data)) > p.maxPage {
		return Release{}, fmt.Errorf("GeoIP release page exceeds size limit")
	}
	return parseRelease(data, role)
}

var dlRE = regexp.MustCompile(`(?is)<dl\b[^>]*>(.*?)</dl>`)
var formatRE = regexp.MustCompile(`(?is)<dt>\s*Format\s*</dt>\s*<dd[^>]*>\s*MMDB\s*</dd>`)
var releaseRE = regexp.MustCompile(`(?is)<dt>\s*Release\s*</dt>\s*<dd[^>]*>\s*([^<]+?)\s*</dd>`)
var shaRE = regexp.MustCompile(`(?is)<dt>\s*SHA1SUM\s*</dt>\s*<dd[^>]*>\s*([a-f0-9]{40})\s*</dd>`)
var hrefRE = regexp.MustCompile(`(?is)\bhref\s*=\s*["']([^"']+)["']`)

func parseRelease(data []byte, role string) (Release, error) {
	var found []Release
	blocks := dlRE.FindAllSubmatchIndex(data, -1)
	for i, idx := range blocks {
		body := data[idx[2]:idx[3]]
		if !formatRE.Match(body) {
			continue
		}
		date, sha := releaseRE.FindSubmatch(body), shaRE.FindSubmatch(body)
		if date == nil || sha == nil {
			continue
		}
		month, err := time.Parse("January 2006", strings.TrimSpace(string(date[1])))
		if err != nil {
			continue
		}
		end := len(data)
		if i+1 < len(blocks) {
			end = blocks[i+1][0]
		}
		for _, m := range hrefRE.FindAllSubmatch(data[idx[1]:end], -1) {
			raw := html.UnescapeString(string(m[1]))
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			parts := downloadPath.FindStringSubmatch(u.Path)
			if len(parts) != 3 || parts[1] != role {
				continue
			}
			if err := allowedURL(raw); err != nil {
				return Release{}, err
			}
			if parts[2] != month.Format("2006-01") {
				return Release{}, fmt.Errorf("GeoIP release page version and download URL disagree")
			}
			found = append(found, Release{Role: role, Version: parts[2], URL: raw, SHA1: strings.ToLower(string(sha[1]))})
		}
	}
	if len(found) != 1 {
		return Release{}, fmt.Errorf("DB-IP %s page changed: expected one MMDB release with URL and SHA1, found %d", role, len(found))
	}
	return found[0], nil
}
func (p *Provider) Fetch(ctx context.Context, r Release, w io.Writer) error {
	body, err := p.get(ctx, r.URL)
	if err != nil {
		return err
	}
	defer body.Close()
	n, err := io.Copy(w, io.LimitReader(body, p.maxDownload+1))
	if err != nil {
		return err
	}
	if n > p.maxDownload {
		return fmt.Errorf("GeoIP compressed download exceeds size limit")
	}
	return nil
}
