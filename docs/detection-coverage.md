# Detection coverage and limits

Planned supported: Apache Common/Combined, Nginx combined, explicit vhost prefix, Nginx JSON with exact canonical keys, optional named-regex mapping. gzip magic, multiple/rotated files and directories. Ambiguous suffixes rejected unless explicitly mapped. No arbitrary Apache LogFormat inference, WAF/body/error-log parsing or trusted proxy inference.

L1: injection (SQL/NoSQL/OS/LDAP/XPath/template), XSS, traversal/LFI/RFI/SSRF, URL-visible XXE, deserialization/RCE, webshell, Log4Shell, Spring4Shell, Struts, CRLF/null bytes, sensitive files, selected CVE probes and IIS probes; scanner UA and unusual methods. Admin routes alone are benign; repeated failed diverse-route probes are behavioral. Unseen CVEs, body-only payloads, obfuscation outside bounded decode variants, actual auth state and filesystem integrity cannot be verified.

L2/L3 need sufficient time/IP/status/size information and bounded retained state. Legitimate crawlers/high-rate API clients may trigger rate anomalies; anomalies are reported as review candidates. No IP reputation, geolocation, live enrichment or outbound connections. Standard access logs cannot confirm compromise; unknown is a valid and expected result. Precision numbers from synthetic fixtures do not predict production performance.
