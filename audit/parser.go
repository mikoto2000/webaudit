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

var standard = regexp.MustCompile(`^(?:(?P<host>[^\s]+) )?(?P<ip>[^\s]+) [^\s]+ [^\s]+ \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" (?P<status>[0-9]{3}|-) (?P<bytes>[0-9]+|-)(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?$`)

func Parse(line, file string, n int64, custom string) (Event, error) {
	if !utf8.ValidString(line) || strings.ContainsAny(line, "\x00\r\n") {
		return Event{}, fmt.Errorf("invalid UTF-8 or control line")
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
		m := standard.FindStringSubmatch(line)
		if m == nil {
			return Event{}, fmt.Errorf("unrecognized layout; expected ip/time/request/status/bytes; use --log-regex with named groups for custom fields")
		}
		for i, name := range standard.SubexpNames() {
			if i > 0 && name != "" {
				fields[name] = m[i]
			}
		}
	}
	return eventFrom(fields, line, file, n)
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
	e := Event{File: file, Line: n, Raw: raw, IP: f["ip"]}
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
		if len(p) != 3 || p[0] == "" || p[1] == "" || !strings.HasPrefix(p[2], "HTTP/") {
			return e, fmt.Errorf("malformed request line; method/target/protocol not inferred")
		}
		f["method"], f["target"], f["protocol"] = p[0], p[1], p[2]
	}
	e.Target = f["target"]
	if e.Target == "" || e.Target == "-" {
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
