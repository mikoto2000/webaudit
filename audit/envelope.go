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

var extendedStandard = regexp.MustCompile(`^(?:(?P<host>[^\s]+) )?(?P<ip>[^\s]+) [^\s]+ [^\s]+ \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" (?P<status>[0-9]{3}|-) (?P<bytes>[0-9]+|-) "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)"(?P<suffix> .+)$`)
var npmPlus = regexp.MustCompile(`^\[(?P<time>[^\]]+)\] (?P<host>\S+) (?P<ip>\S+) [0-9.]+ "(?P<request>[^"]*)" (?P<status>[0-9]{3}) (?P<bytes>[0-9]+) [0-9]+ (?P<referer>\S+) (?P<ua>.*)$`)
var nginxErrTime = regexp.MustCompile(`^(?:\S+ )?(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[[a-z]+\]`)
var apacheErrTime = regexp.MustCompile(`^\[([A-Za-z]{3} [A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.[0-9]+)? \d{4})\]`)
var errorClient = regexp.MustCompile(`(?:, client: |\[client )([^,\] ]+(?::[0-9]+)?|\[[0-9a-fA-F:]+\]:[0-9]+)`)
var errorReq = regexp.MustCompile(`request: "((?:[^"\\]|\\.)*)"`)
var invalidURI = regexp.MustCompile(`Invalid URI in request (.*?)(?: +|$)$`)
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
	if req == "" {
		return Event{}, true, fmt.Errorf("error log lacks an HTTP request")
	}
	if ts.IsZero() {
		return Event{}, true, fmt.Errorf("invalid error-log timestamp")
	}
	e, err := eventFrom(map[string]string{"ip": ip, "time": ts.Format(time.RFC3339), "request": req}, raw, file, n)
	if err != nil {
		return e, true, err
	}
	e.TimezoneUnknown = true
	e.WallTime = ptr(wall)
	e.LogType = "http_error-log"
	e.AuthFailure = strings.Contains(body, "password mismatch") || strings.Contains(body, "was not found in")
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
