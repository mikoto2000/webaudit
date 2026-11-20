package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var requestMethod = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
var requestVersion = regexp.MustCompile(`^HTTP/[+-]?[0-9]+(?:\.[0-9]+)?$`)
var standard = regexp.MustCompile(`^(?:(?P<host>[^\s]+) )?(?P<ip>[0-9a-fA-F:.]+) [^\s]+ (?:[^\s]+ )?\[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" (?P<status>[0-9]{3}|-) (?P<bytes>[0-9]+|-)(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?$`)

func Parse(line, file string, n int64, custom string) (Event, error) {
	if !utf8.ValidString(line) || strings.ContainsAny(line, "\x00\r\n") {
		return Event{}, fmt.Errorf("invalid UTF-8 or control line")
	}
	original := line
	envelope := ""
	if custom == "" {
		var err error
		line, envelope, err = unwrapSyslog(line)
		if err != nil {
			return Event{}, err
		}
		if e, ok, err := parseError(line, original, file, n); ok {
			if envelope != "" {
				e.Envelope = ptr(envelope)
			}
			return e, err
		}
	}
	fields := map[string]string{}
	if custom != "" {
		rx, err := regexp.Compile(custom)
		if err != nil {
			return Event{}, fmt.Errorf("custom regex: %w", err)
		}
		m := rx.FindStringSubmatch(line)
		if m == nil || m[0] != line {
			return Event{}, fmt.Errorf("custom regex does not match whole line")
		}
		for i, name := range rx.SubexpNames() {
			if i > 0 && name != "" {
				fields[name] = m[i]
			}
		}
	} else if strings.HasPrefix(strings.TrimSpace(line), "{") {
		obj, err := uniqueObject(line)
		if err != nil {
			return Event{}, fmt.Errorf("invalid JSON: %w", err)
		}
		for key, dest := range map[string]string{"remote_addr": "ip", "time_local": "time", "time_iso8601": "time", "request": "request", "status": "status", "body_bytes_sent": "bytes", "http_user_agent": "ua", "http_referer": "referer", "host": "host"} {
			if v, ok := obj[key]; ok && string(v) != "null" {
				var s string
				if json.Unmarshal(v, &s) != nil {
					s = string(v)
				}
				if _, exists := fields[dest]; exists {
					return Event{}, fmt.Errorf("ambiguous JSON field %s", dest)
				}
				fields[dest] = s
			}
		}
	} else {
		fields = fieldsFrom(standard, line)
		if fields == nil {
			fields = fieldsFrom(extendedStandard, line)
		}
		if fields == nil {
			fields = fieldsFrom(npmPlus, line)
		}
		if fields == nil {
			fields = fieldsFrom(npmLegacy, line)
		}
		if fields == nil {
			return Event{}, fmt.Errorf("unrecognized layout; expected ip/time/request/status/bytes; use --log-regex with named groups for custom fields")
		}

	}
	e, err := eventFrom(fields, original, file, n)
	if envelope != "" {
		e.Envelope = ptr(envelope)
	}
	return e, err
}
func uniqueObject(line string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(strings.NewReader(line))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("expected object")
	}
	obj := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, err
		}
		k, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("expected field name")
		}
		if _, exists := obj[k]; exists {
			return nil, fmt.Errorf("duplicate JSON field %s", k)
		}
		var v json.RawMessage
		if err = d.Decode(&v); err != nil {
			return nil, err
		}
		obj[k] = v
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return obj, nil
}
func eventFrom(f map[string]string, raw, file string, n int64) (Event, error) {
	e := Event{File: file, Line: n, Raw: raw, IP: f["ip"], LogType: "http_access-log"}
	if ua, ok := f["ua"]; ok {
		e.RecordedUA = ptr(ua)
	}
	if ref, ok := f["referer"]; ok {
		e.RecordedReferer = ptr(ref)
	}
	if _, err := netip.ParseAddr(e.IP); err != nil {
		return e, fmt.Errorf("invalid/missing client IP (recognized time/request/status); hostnames and XFF not trusted")
	}
	var err error
	e.Time, err = time.Parse("02/Jan/2006:15:04:05 -0700", f["time"])
	if err != nil {
		e.Time, err = time.Parse(time.RFC3339Nano, f["time"])
	}
	if err != nil {
		return e, fmt.Errorf("invalid/missing timestamp")
	}
	if req := f["request"]; req != "" {
		p := strings.Split(req, " ")
		e.RawRequest = ptr(req)
		if len(p) == 2 && requestMethod.MatchString(p[0]) && p[1] != "" {
			f["method"], f["target"] = p[0], p[1]
		} else if len(p) != 3 || !requestMethod.MatchString(p[0]) || p[1] == "" || !requestVersion.MatchString(p[2]) {
			e.RequestMalformed = true
		} else {
			f["method"], f["target"], f["protocol"] = p[0], p[1], p[2]
		}
	}
	e.Target = f["target"]
	if (e.Target == "" || e.Target == "-") && !e.RequestMalformed {
		return e, fmt.Errorf("missing request target")
	}
	e.Path = e.Target
	if i := strings.IndexByte(e.Target, '?'); i >= 0 {
		e.Path = e.Target[:i]
		e.Query = ptr(e.Target[i+1:])
	}
	optional := func(k string) *string {
		s := f[k]
		if s == "" || s == "-" {
			return nil
		}
		return ptr(s)
	}
	e.Suffix = optional("suffix")
	e.Host = optional("host")
	e.Method = optional("method")
	e.Protocol = optional("protocol")
	e.UA = optional("ua")
	e.Referer = optional("referer")
	if s := f["status"]; s != "" && s != "-" {
		v, er := strconv.Atoi(s)
		if er != nil || v < 100 || v > 599 {
			return e, fmt.Errorf("invalid status")
		}
		e.Status = ptr(v)
	}
	if s := f["bytes"]; s != "" && s != "-" {
		v, er := strconv.ParseInt(s, 10, 64)
		if er != nil || v < 0 {
			return e, fmt.Errorf("invalid response size")
		}
		e.Bytes = ptr(v)
	}
	return e, nil
}
