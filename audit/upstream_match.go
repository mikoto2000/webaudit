package audit

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
)

type sourceView struct {
	full     string
	req      string
	args     string
	lower    string
	upper    string
	dir      string
	frag     string
	filename string
	ext      string
	qu       string
	pu       string
	static   bool
}

func makeSourceView(e Event) sourceView {
	full := sourceField(e, "evt.Meta.http_path")
	req := sourceField(e, "evt.Parsed.request")
	args := sourceField(e, "evt.Parsed.http_args")
	lower := strings.ToLower(full)
	upper := strings.ToUpper(full)
	dir, frag, extension := sourceFile(req)
	filename := frag + extension
	ext := strings.TrimPrefix(extension, ".")
	static := strings.Contains("|JPG|CSS|JS|JPEG|PNG|SVG|MAP|ICO|OTF|GIF|MP3|MP4|WOFF|WOFF2|TTF|EOT|WEBP|WAV|GZ|BROTLI|BVR|TS|BMP|AVIF|MJS|TGZ|", "|"+strings.ToUpper(ext)+"|") && ext != ""
	qu, err := url.QueryUnescape(full)
	if err != nil {
		qu = full
	}
	pu, err := url.PathUnescape(full)
	if err != nil {
		pu = full
	}
	return sourceView{full: full, req: req, args: args, lower: lower, upper: upper, dir: dir, frag: frag, filename: filename, ext: ext, qu: qu, pu: pu, static: static}
}

var sourceRX sync.Map
var sourceLookups = map[string][]map[string]string{}
var sourceFileRX = regexp.MustCompile(`^(.*/)(?:([^/].*?)(\.[^.]*$|$))?`)

func sourceFile(req string) (dir, frag, ext string) {
	m := sourceFileRX.FindStringSubmatch(req)
	if m != nil {
		return m[1], m[2], m[3]
	}
	return "", "", ""
}

func sourceRE(p, s string) bool {
	v, ok := sourceRX.Load(p)
	if !ok {
		v = regexp.MustCompile(p)
		sourceRX.Store(p, v)
	}
	return v.(*regexp.Regexp).MatchString(s)
}
func listContains(name, s string, fold bool) bool {
	if fold {
		s = strings.ToUpper(s)
	}
	for _, p := range sourceLists[name] {
		if fold {
			p = strings.ToUpper(p)
		}
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
func listExact(name, s string) bool {
	for _, p := range sourceLists[name] {
		if s == p {
			return true
		}
	}
	return false
}
func listSuffix(name, s string) bool {
	for _, p := range sourceLists[name] {
		if strings.HasSuffix(s, p) {
			return true
		}
	}
	return false
}
func sourceLookup(name, s, key string) bool {
	if key == "" {
		return lookupTag(name, s) != ""
	}
	for _, row := range sourceLookups[name] {
		if key != "" {
			if strings.Contains(s, row[key]) {
				return true
			}
			continue
		}
		if lookupRow(row, s) {
			return true
		}
	}
	return false
}
func lookupTag(name, s string) string {
	rows := sourceLookups[name]
	tag := ""
	for _, row := range rows {
		if row["type"] == "equals" && row["pattern"] == s {
			tag = row["tag"]
		}
	}
	if tag != "" {
		return tag
	}
	pos := -1
	for _, row := range rows {
		if row["type"] == "contains" {
			i := strings.Index(s, row["pattern"])
			if i >= 0 && (pos < 0 || i < pos) {
				pos = i
				tag = row["tag"]
			}
		}
	}
	if tag != "" {
		return tag
	}
	for _, row := range rows {
		if row["type"] == "regex" && sourceRE(row["pattern"], s) {
			return row["tag"]
		}
	}
	return ""
}
func lookupRow(row map[string]string, s string) bool {
	switch row["type"] {
	case "equals":
		return s == row["pattern"]
	case "contains":
		return strings.Contains(s, row["pattern"])
	case "regex":
		return sourceRE(row["pattern"], s)
	}
	return false
}
func sourceMatch(r SourceRule, e Event) bool { return sourceMatchView(r, e, makeSourceView(e)) }
func sourceMatchView(r SourceRule, e Event, v sourceView) bool {
	if e.LogType != "http_access-log" && e.LogType != "http_error-log" {
		return false
	}
	full := v.full
	req := v.req
	args := v.args
	lower := v.lower
	upper := v.upper
	qu := v.qu
	pu := v.pu
	dir, frag, filename, ext := v.dir, v.frag, v.filename, v.ext
	static := v.static
	status := val(e.Status)
	verb := val(e.Method)
	access := e.LogType == "http_access-log"
	denied := status == 403 || status == 404
	id := r.ID[strings.IndexByte(r.ID, '/')+1:]
	switch id {
	case "apache_log4j2_cve-2021-44228":
		return listContains("log4j2_cve_2021_44228.txt", full, true) || listContains("log4j2_cve_2021_44228.txt", sourceUA(e), true) || listContains("log4j2_cve_2021_44228.txt", sourceReferer(e), true)
	case "CVE-2017-9841":
		return access && strings.HasSuffix(lower, "util/php/eval-stdin.php")
	case "CVE-2019-18935":
		return strings.HasPrefix(strings.ToUpper(qu), strings.ToUpper("/Telerik.Web.UI.WebResource.axd?type=rau"))
	case "CVE-2022-26134":
		return strings.Contains(strings.ToUpper(pu), strings.ToUpper("@java.lang.Runtime@getRuntime().exec("))
	case "CVE-2022-35914":
		return strings.Contains(upper, strings.ToUpper("/vendor/htmlawed/htmlawed/htmLawedTest.php"))
	case "CVE-2022-37042":
		return strings.ToUpper(verb) == "POST" && status >= 400 && status < 410 && (strings.Contains(upper, "/SERVICE/EXTENSION/BACKUP/MBOXIMPORT?ACCOUNT-NAME=ADMIN&OW=2&NO-SWITCH=1&APPEND=1") || strings.Contains(upper, "/SERVICE/EXTENSION/BACKUP/MBOXIMPORT?ACCOUNT-NAME=ADMIN&ACCOUNT-STATUS=1&OW=CMD"))
	case "fortinet-cve-2022-40684":
		return strings.HasPrefix(upper, "/API/V2/CMDB/SYSTEM/ADMIN/") && strings.ToLower(val(e.UA)) == "report runner"
	case "CVE-2022-41082":
		return strings.Contains(upper, "/AUTODISCOVER/AUTODISCOVER.JSON") && strings.Contains(strings.ToUpper(args), "POWERSHELL")
	case "CVE-2022-41697":
		return strings.Contains(upper, "/GHOST/API/ADMIN/SESSION") && strings.ToUpper(verb) == "POST" && status == 404
	case "CVE-2022-42889":
		return strings.Contains(strings.ToUpper(pu), "${SCRIPT:JAVASCRIPT:JAVA.LANG.RUNTIME.GETRUNTIME().EXEC(") || strings.Contains(strings.ToUpper(pu), "${SCRIPT:JS:JAVA.LANG.RUNTIME.GETRUNTIME().EXEC(") || strings.Contains(strings.ToUpper(pu), "${URL:UTF-8:") || strings.Contains(strings.ToUpper(pu), "${DNS:ADDRESS|")
	case "CVE-2022-44877":
		return strings.ToUpper(verb) == "POST" && status == 302 && strings.Contains(lower, "/index.php") && sourceRE(`login=.*(\$|%24)(\(|%28).*(\)|%29)`, strings.ToLower(args))
	case "CVE-2022-46169-bf":
		return strings.ToUpper(verb) == "GET" && strings.Contains(upper, "/REMOTE_AGENT.PHP") && strings.Contains(strings.ToLower(args), "host_id") && strings.Contains(strings.ToLower(args), "local_data_ids")
	case "CVE-2022-46169-cmd":
		return strings.ToUpper(verb) == "GET" && strings.Contains(upper, "/REMOTE_AGENT.PHP") && strings.Contains(strings.ToLower(args), "action=polldata") && sourceRE(`poller_id=.*(;|%3b)`, strings.ToLower(args))
	case "CVE-2023-22515":
		return strings.ToLower(ext) == "action" && (strings.Contains(strings.ToLower(dir), "/setup") || strings.ToLower(frag) == "server-info")
	case "CVE-2023-22518":
		return strings.ToUpper(verb) == "POST" && strings.Contains(upper, "/JSON/SETUP-RESTORE.ACTION")
	case "CVE-2023-49103":
		return strings.Contains(lower, "/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/getphpinfo.php")
	case "CVE-2024-0012":
		return denied && (sourceRE(`/php/.*/\.js\.map`, strings.ToLower(req)) || sourceRE(`/index.php/.*\.js\.map`, strings.ToLower(req)))
	case "CVE-2024-38475":
		return denied && strings.HasSuffix(strings.ToLower(req), "%3f")
	case "CVE-2024-9474":
		return denied && verb == "POST" && strings.Contains(strings.ToLower(req), "/php/utils/createremoteappwebsession.php/watchtowr.js.map")
	case "f5-big-ip-cve-2020-5902":
		return sourceRE(`/TMUI/LOGIN.JSP/..;/TMUI/[^.]+.JSP\?(FILENAME|COMMAND|DIRECTORYPATH|TABID)=`, upper) || sourceRE(`/TMUI/LOGIN.JSP/%2E%2E;/TMUI/[^.]+.JSP\?(FILENAME|COMMAND|DIRECTORYPATH|TABID)=`, upper)
	case "fortinet-cve-2018-13379":
		return strings.Contains(upper, "/REMOTE/FGT_LANG?LANG=/../../../..//////////DEV/CMDB/SSLVPN_WEBSESSION")
	case "grafana-cve-2021-43798":
		return sourceRE(`/PUBLIC/PLUGINS/[^/]+/../[./]+/`, upper) || sourceRE(`/PUBLIC/PLUGINS/[^/]+/%2E%2E/[%2E/]+/`, upper)
	case "http-admin-interface-probing":
		return denied && listContains("admin_interfaces.txt", lower, false)
	case "http-apiscp-bf":
		return access && verb == "POST" && status == 200 && strings.HasPrefix(full, "/apps/login")
	case "http-backdoors-attempts":
		return listExact("backdoors.txt", filename)
	case "http-bad-user-agent":
		return matchPatterns(dataPatterns["bad_user_agents.regex.txt"], sourceUA(e))
	case "http-bf-wordpress_bf":
		return access && filename == "wp-login.php" && verb == "POST" && status == 200
	case "http-bf-wordpress_bf_xmlrpc":
		return access && filename == "xmlrpc.php" && verb == "POST"
	case "http-crawl-non_statics":
		return !static && (verb == "GET" || verb == "HEAD")
	case "http-cve-2021-41773":
		return strings.Contains(upper, "/.%2E/.%2E/") || strings.Contains(upper, "/%2E%2E/%2E%2E")
	case "http-cve-2021-42013":
		return strings.Contains(upper, "/%%32%65%%32%65/")
	case "http-cve-probing":
		return denied && sourceLookup("trendy_cves_uris.json", full, "uri")
	case "http-dos-bypass-cache":
		return access && !static && sourceRE(`^[0-9]{7,12}$`, args)
	case "http-dos-invalid-http-versions":
		p := strings.TrimPrefix(val(e.Protocol), "HTTP/")
		return p != "" && p != "0.9" && p != "1.0" && p != "1.1" && p != "2.0" && p != "3.0"
	case "http-dos-random-uri":
		return access && verb == "GET" && !static && strings.ToUpper(frag) == frag && len(frag) == 6 && args == ""
	case "http-dos-swithcing-ua":
		return true
	case "http-generic-bf":
		return e.AuthFailure
	case "http-generic-401-bf":
		return access && verb == "POST" && status == 401
	case "http-generic-403-bf":
		return access && verb == "POST" && status == 403
	case "http-generic-test":
		return full == "/crowdsec-test-NtktlJHV4TfBSK3wvlhiOBnl"
	case "http-open-proxy":
		return access && (status == 400 || status == 405) && (verb == "CONNECT" || sourceRE(`^http[s]?://`, req))
	case "http-path-traversal-probing":
		return listContains("path_traversal.txt", full, false)
	case "http-probing":
		return (status == 400 || denied) && !static
	case "http-sap-interface-probing":
		if !denied {
			return false
		}
		if lower == "/nwa" {
			return true
		}
		for _, s := range []string{"/sap/bc/gui/sap/its/webgui", "/irj/portal", "/sap/bc/", "/sap/opu/odata/", "/sap/public/bc/", "/sap/public/info", "/sap/public/icf_info", "/sap/admin/publicicp/", "/sap/admin/public/", "/webdynpro/dispatcher/sap.com/tc~sec~ume~wd~umeadmin/umeadminapp", "/sap/hana/xs/admin", "/sap/hana/xs/formlogin", "/irj/go/km/navigation"} {
			if strings.Contains(lower, s) {
				return true
			}
		}
		return false
	case "http-sensitive-files":
		return listSuffix("sensitive_data.txt", req)
	case "http-sqli-probbing-detection":
		return listContains("sqli_probe_patterns.txt", args, true)
	case "http-technology-probing":
		return denied && sourceLookup("technology_probing.json", full, "")
	case "http-wordpress-scan":
		return denied && sourceRE(`(?i)(/wp-.*\.php|/wp-content/plugins/.*\.(txt|md))$`, strings.ToLower(req))
	case "http-wordpress_user-enum":
		return access && strings.Contains(strings.ToUpper(args), "AUTHOR=")
	case "http-wordpress_wpconfig":
		return access && strings.Contains(filename, "wp-config.php")
	case "http-xss-probbing":
		return listContains("xss_probe_patterns.txt", args, true)
	case "jira_cve-2021-26086":
		return listContains("jira_cve_2021-26086.txt", full, true)
	case "netgear_rce":
		return strings.HasPrefix(strings.ToLower(qu), "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=")
	case "pulse-secure-sslvpn-cve-2019-11510":
		return sourceRE(`/DANA-NA/../DANA/HTML5ACC/GUACAMOLE/../../../../../../../[^?]+\?/DANA/HTML5ACC/GUACAMOLE/`, upper) || sourceRE(`/DANA-NA/%2E%2E/DANA/HTML5ACC/GUACAMOLE/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/[^?]+\?/DANA/HTML5ACC/GUACAMOLE/`, upper)
	case "spring4shell_cve-2022-22965":
		return strings.Contains(upper, "CLASS.MODULE.CLASSLOADER.")
	case "thinkphp-cve-2018-20062":
		return matchPatterns(dataPatterns["thinkphp_cve_2018-20062.txt"], lower)
	case "vmware-cve-2022-22954":
		return strings.HasPrefix(strings.ToUpper(qu), strings.ToUpper(`/catalog-portal/ui/oauth/verify?error=&deviceUdid=${"freemarker.template.utility.Execute"?new()(`))
	case "http-w00tw00t":
		return access && (strings.Contains(filename, "w00tw00t.at.ISC.SANS.DFind") || lower == "/core/skin/login.aspx")
	case "vmware-vcenter-vmsa-2021-0027":
		return sourceRE(`/ui/vcav-bootstrap/rest/vcav-providers/provider-logo\?url=(file|http)`, full)
	}
	return false
}
