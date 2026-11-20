package audit

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	n := Normalize(`/a%252f..%252fetc%252fpasswd?q=a+b%ZZ`)
	if n.Original != `/a%252f..%252fetc%252fpasswd?q=a+b%ZZ` || len(n.Variants) > 7 || len(n.Steps) == 0 || !strings.Contains(strings.Join(n.Variants, "\n"), "../etc/passwd") || len(n.Warnings) == 0 {
		t.Fatalf("%+v", n)
	}
	n = Normalize(`/日本語?q=%253cscript%253e`)
	if !strings.Contains(strings.Join(n.Variants, "\n"), "<script>") {
		t.Fatal(n)
	}
	n = Normalize(`/a%2525252f`)
	if strings.Contains(strings.Join(n.Variants, "\n"), "/a/") {
		t.Fatal("unbounded decode", n)
	}
}
func TestSignatures(t *testing.T) {
	cases := []struct{ id, url string }{
		{"sqli", "/?q=1%27+OR+1=1--"}, {"nosqli", "/?filter[$ne]=1"},
		{"command_injection", "/?x=%3bwhoami"}, {"shellshock", "/?x=() { :;};"},
		{"ssti", "/?x={{7*7}}"}, {"ldap_injection", "/?x=*)(uid=*"},
		{"xpath_injection", "/?x=/child::user"}, {"xss", "/?x=%253cscript%253e"},
		{"lfi_traversal", "/a/../../etc/passwd"}, {"rfi", "/?include=https://evil.example/x"},
		{"ssrf", "/?url=http://169.254.169.254/latest/meta-data"}, {"xxe", "/?x=<!ENTITY+x+SYSTEM+%22file:///etc/passwd%22>"},
		{"deserialization", "/?x=java.lang.Runtime"}, {"webshell", "/shell.php?cmd=id"},
		{"log4shell", "/?x=${jndi:ldap://invalid/x}"}, {"spring4shell", "/?class.module.classLoader.x=1"},
		{"struts_ognl", "/?x=_memberAccess"}, {"crlf_injection", "/?x=%0d%0aSet-Cookie:x"},
		{"open_redirect", "/?redirect=//evil.example"}, {"access_bypass", "/..;/manager/html"},
		{"sensitive_file", "/.env"}, {"sensitive_file", "/id_rsa"}, {"cve_probe", "/wls-wsat/x"}, {"null_byte", "/?x=%00"},
		{"cve_probe", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"},
		{"iis_aspnet", "/trace.axd"}, {"recon_probe", "/api/../private"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			e := Event{Target: c.url}
			hits, _ := Detect(e)
			found := false
			for _, h := range hits {
				if h.ID == "WA-"+c.id {
					found = true
				}
				if h.Description == "" || len(h.Required) == 0 || h.Severity == "" {
					t.Fatal(h)
				}
			}
			if !found {
				t.Fatalf("missing %s: %+v", c.id, hits)
			}
		})
	}
	for _, url := range []string{"/", "/admin", "/wp-admin/", "/graphql", "/search?q=union+meeting", "/fetch?url=https://example.org/picture", "/.well-known/security.txt", "/api/items?x=0x1234", "/catalog?q=日本語"} {
		hits, _ := Detect(Event{Target: url, Method: ptr("PATCH"), UA: ptr("curl/8")})
		if len(hits) != 0 {
			t.Fatalf("false positive on %s: %+v", url, hits)
		}
	}
	for _, e := range []Event{{UA: ptr("sqlmap/1")}, {Method: ptr("TRACE")}, {UA: ptr("${jndi:ldap://invalid/a}")}} {
		h, _ := Detect(e)
		if len(h) == 0 {
			t.Fatal(e)
		}
	}
}
func TestRulesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.ID] {
			t.Fatal(r.ID)
		}
		seen[r.ID] = true
	}
	if len(seen) != 28 {
		t.Fatal(len(seen))
	}
}
