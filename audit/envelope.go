package audit

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

var rfc3164 = regexp.MustCompile(`^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ [^ :]+(?:\[[0-9]+\])?: `)
var rfc5424 = regexp.MustCompile(`^<[0-9]{1,3}>[1-9][0-9]* \S+ \S+ \S+ \S+ \S+ `)

func unwrapSyslog(s string) (string, string, error) {
	if strings.HasPrefix(s, "{") {
		var envelope struct{ Type, Message string }
		obj, err := uniqueObject(s)
		if err != nil {
			return "", "", err
		}
		_ = json.Unmarshal(obj["type"], &envelope.Type)
		_ = json.Unmarshal(obj["message"], &envelope.Message)
		if envelope.Type == "log.journald" {
			if i := strings.Index(envelope.Message, " nginx: "); i >= 0 {
				return envelope.Message[i+8:], "upsun/journald", nil
			}
		}
	}
	if p := rfc3164.FindString(s); p != "" {
		return s[len(p):], p, nil
	}
	if p := rfc5424.FindString(s); p != "" {
		tail := s[len(p):]
		i := 0
		if strings.HasPrefix(tail, "-") {
			i = 1
		} else {
			for i < len(tail) && tail[i] == '[' {
				quoted, escaped := false, false
				i++
				closed := false
				for i < len(tail) {
					c := tail[i]
					i++
					if escaped {
						escaped = false
						continue
					}
					if c == '\\' {
						escaped = true
						continue
					}
					if c == '"' {
						quoted = !quoted
					}
					if c == ']' && !quoted {
						closed = true
						break
					}
				}
				if !closed {
					return "", "", fmt.Errorf("unterminated syslog structured data")
				}
			}
		}
		if i == 0 || i >= len(tail) || tail[i] != ' ' {
			return "", "", fmt.Errorf("invalid syslog structured data")
		}
		i++
		return tail[i:], s[:len(p)+i], nil
	}
	return s, "", nil
}

var extendedStandard = regexp.MustCompile(`^(?:(?P<host>[^\s]+) )?(?P<ip>[0-9a-fA-F:.]+) [^\s]+ (?:[^\s]+ )?\[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" (?P<status>[0-9]{3}|-) (?P<bytes>[0-9]+|-) "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)"(?P<suffix> .+)$`)
var npmPlus = regexp.MustCompile(`^\[(?P<time>[^\]]+)\] (?P<host>\S+) (?P<ip>\S+) [0-9.]+ "(?P<request>[^"]*)" (?P<status>[0-9]{3}) (?P<bytes>[0-9]+) [0-9]+ (?P<referer>\S+) (?P<ua>.*)$`)
var npmLegacy = regexp.MustCompile(`^\[(?P<time>[^\]]+)\](?: (?:HIT|MISS|BYPASS|EXPIRED|STALE|UPDATING|REVALIDATED|-) (?:-|[0-9]*))? (?P<status>[0-9]{3}) - (?P<method>\w+) \w+ (?P<host>\S+) "(?P<target>[^"]*)" \[Client (?P<ip>[^\]]+)\] \[Length (?P<bytes>[0-9]+)\] \[Gzip [^\]]*\](?: \[Sent-to [^\]]*\])? "(?P<ua>[^"]*)" "(?P<referer>[^"]*)"$`)
var nginxErrTime = regexp.MustCompile(`^(?:\S+ )?(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[[a-z]+\]`)
var apacheErrTime = regexp.MustCompile(`^\[([A-Za-z]{3} [A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.[0-9]+)? \d{4})\]`)
var errorClient = regexp.MustCompile(`(?:, client: ([^, ]+)|\[client (\[[^\]]+\](?::[0-9]+)?|[^ ]+)\])`)
var errorReq = regexp.MustCompile(`request: "((?:[^"\\]|\\.)*)"`)
var invalidURI = regexp.MustCompile(`Invalid URI in request (.*?)(?: +|$)$`)
var apacheAuth = regexp.MustCompile(`\[auth_basic:[^\]]+\].*authentication failure for "([^"]+)": Password Mismatch`)
var apacheNotFound = regexp.MustCompile(`\[auth_basic:[^\]]+\].*user [^:]+ not found: "?([^" ]+)"?`)
var apacheDenied = regexp.MustCompile(`\[authz_core:[^\]]+\].*client denied by server configuration: (.*)$`)
var errorHost = regexp.MustCompile(`server: ([^,]*),`)

func fieldsFrom(rx *regexp.Regexp, s string) map[string]string {
	m := rx.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	f := map[string]string{}
	for i, n := range rx.SubexpNames() {
		if i > 0 && n != "" {
			f[n] = m[i]
		}
	}
	return f
}
func parseError(body, raw, file string, n int64) (Event, bool, error) {
	var ts time.Time
	wall := ""
	if m := nginxErrTime.FindStringSubmatch(body); m != nil {
		wall = m[1]
		ts, _ = time.Parse("2006/01/02 15:04:05", wall)
	} else if m := apacheErrTime.FindStringSubmatch(body); m != nil {
		wall = m[1]
		ts, _ = time.Parse("Mon Jan _2 15:04:05.999999999 2006", wall)
	} else {
		return Event{}, false, nil
	}
	m := errorClient.FindStringSubmatch(body)
	if m == nil {
		return Event{}, true, fmt.Errorf("error log lacks client IP")
	}
	ip := m[1]
	if ip == "" {
		ip = m[2]
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		} else if i := strings.LastIndexByte(ip, ':'); i >= 0 {
			candidate := ip[:i]
			if _, err := netip.ParseAddr(candidate); err == nil {
				ip = candidate
			}
		}
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return Event{}, true, fmt.Errorf("invalid error-log peer IP")
	}
	req := ""
	if m := errorReq.FindStringSubmatch(body); m != nil {
		req = m[1]
	} else if m := invalidURI.FindStringSubmatch(body); m != nil {
		req = strings.TrimSpace(m[1])
	}
	targetOnly := ""
	subType := ""
	if req == "" {
		if m := apacheAuth.FindStringSubmatch(body); m != nil {
			targetOnly = m[1]
			subType = "auth_fail"
		}
		if m := apacheNotFound.FindStringSubmatch(body); m != nil {
			targetOnly = m[1]
			subType = "auth_fail"
		}
		if m := apacheDenied.FindStringSubmatch(body); m != nil {
			targetOnly = m[1]
			subType = "permission_denied"
		}
	}
	if req == "" && targetOnly == "" && nginxErrTime.MatchString(body) {
		return Event{}, true, fmt.Errorf("Nginx entry lacks HTTP request; mail/stream logs require another parser")
	}

	if ts.IsZero() {
		return Event{}, true, fmt.Errorf("invalid error-log timestamp")
	}
	fields := map[string]string{"ip": ip, "time": ts.Format(time.RFC3339Nano), "request": req}
	if targetOnly != "" {
		fields["target"] = targetOnly
	}
	parts := strings.Split(req, " ")
	if len(parts) == 2 {
		fields["method"] = parts[0]
		fields["target"] = parts[1]
		fields["request"] = ""
	}
	var e Event
	var err error
	if req == "" && targetOnly == "" {
		e = Event{IP: ip, Time: ts, File: file, Line: n, Raw: raw}
	} else {
		e, err = eventFrom(fields, raw, file, n)
	}
	if len(parts) == 2 {
		e.RawRequest = ptr(req)
	}
	if targetOnly != "" {
		e.SourceRequest = ptr("")
	}

	if err != nil {
		return e, true, err
	}
	e.TimezoneUnknown = true
	e.WallTime = ptr(wall)
	e.LogType = "http_error-log"
	e.AuthFailure = subType == "auth_fail" || strings.Contains(body, "password mismatch") || strings.Contains(body, "was not found in")
	if e.AuthFailure {
		subType = "auth_fail"
	}
	if strings.Contains(body, "Invalid URI") {
		subType = "invalid_uri"
	}
	e.SubType = subType
	if m := errorHost.FindStringSubmatch(body); m != nil && m[1] != "" {
		e.Host = ptr(m[1])
	}
	return e, true, nil
}

// A timezone-free wall clock is not serialized as a verified UTC instant.
func (e Event) MarshalJSON() ([]byte, error) {
	type alias Event
	var t *time.Time
	if !e.TimezoneUnknown {
		t = &e.Time
	}
	return json.Marshal(struct {
		alias
		Time *time.Time `json:"time"`
	}{alias(e), t})
}
