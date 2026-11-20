# Rule inventory

The original `target` and `legacy_target` columns in rule-inventory.json describe WebAudit's 0.1 narrowed adaptations. They are not used for upstream result comparison. `upstream_target` and `upstream_status` describe the 0.2 source-ID engine. Full pinned Hub expressions and bucket settings are embedded in audit/upstream/hub.json.

Scope: 25 Aura Python URL signatures, scanner UA and method lists, five offline case aggregate rules; 63 selected Hub documents, including 59 HTTP-observable conditions and four unavailable Magento application-event/enrichment conditions. Other Hub OS, AppSec/body and product-specific log formats are outside this Apache/Nginx CLI scope.

| Hub rule | Implemented | Native scenario alert fixture |
|---|---|---|
| crowdsecurity/CVE-2017-9841 | yes | yes |
| crowdsecurity/CVE-2019-18935 | yes | yes |
| crowdsecurity/CVE-2022-26134 | yes | yes |
| crowdsecurity/CVE-2022-35914 | yes | yes |
| crowdsecurity/CVE-2022-37042 | yes | yes |
| crowdsecurity/fortinet-cve-2022-40684 | yes | yes |
| crowdsecurity/CVE-2022-41082 | yes | no; not claimed as fixture-verified |
| crowdsecurity/CVE-2022-41697 | yes | yes |
| crowdsecurity/CVE-2022-42889 | yes | yes |
| crowdsecurity/CVE-2022-44877 | yes | yes |
| crowdsecurity/CVE-2022-46169-bf | yes | yes |
| crowdsecurity/CVE-2022-46169-cmd | yes | yes |
| crowdsecurity/CVE-2023-22515 | yes | yes |
| crowdsecurity/CVE-2023-22518 | yes | yes |
| crowdsecurity/CVE-2023-49103 | yes | yes |
| crowdsecurity/CVE-2024-0012 | yes | yes |
| crowdsecurity/CVE-2024-38475 | yes | yes |
| crowdsecurity/CVE-2024-9474 | yes | yes |
| crowdsecurity/apache_log4j2_cve-2021-44228 | yes | yes |
| crowdsecurity/f5-big-ip-cve-2020-5902 | yes | yes |
| crowdsecurity/fortinet-cve-2018-13379 | yes | yes |
| crowdsecurity/grafana-cve-2021-43798 | yes | yes |
| crowdsecurity/http-admin-interface-probing | yes | yes |
| crowdsecurity/http-apiscp-bf | yes | yes |
| crowdsecurity/http-backdoors-attempts | yes | yes |
| crowdsecurity/http-bad-user-agent | yes | yes |
| crowdsecurity/http-bf-wordpress_bf | yes | yes |
| crowdsecurity/http-bf-wordpress_bf_xmlrpc | yes | no; not claimed as fixture-verified |
| crowdsecurity/http-crawl-non_statics | yes | no; not claimed as fixture-verified |
| crowdsecurity/http-cve-2021-41773 | yes | yes |
| crowdsecurity/http-cve-2021-42013 | yes | yes |
| crowdsecurity/http-cve-probing | yes | yes |
| crowdsecurity/http-dos-bypass-cache | yes | yes |
| crowdsecurity/http-dos-invalid-http-versions | yes | yes |
| crowdsecurity/http-dos-random-uri | yes | yes |
| crowdsecurity/http-dos-swithcing-ua | yes | yes |
| crowdsecurity/http-generic-bf | yes | yes |
| LePresidente/http-generic-401-bf | yes | yes |
| LePresidente/http-generic-403-bf | yes | no; not claimed as fixture-verified |
| crowdsecurity/http-generic-test | yes | yes |
| crowdsecurity/http-magento-bf | requires application/enrichment input | no; not claimed as fixture-verified |
| crowdsecurity/http-magento-ccs-by-as | requires application/enrichment input | no; not claimed as fixture-verified |
| crowdsecurity/http-magento-ccs-by-country | requires application/enrichment input | no; not claimed as fixture-verified |
| crowdsecurity/http-magento-ccs | requires application/enrichment input | no; not claimed as fixture-verified |
| crowdsecurity/http-open-proxy | yes | yes |
| crowdsecurity/http-path-traversal-probing | yes | yes |
| crowdsecurity/http-probing | yes | yes |
| crowdsecurity/http-sap-interface-probing | yes | yes |
| crowdsecurity/http-sensitive-files | yes | yes |
| crowdsecurity/http-sqli-probbing-detection | yes | yes |
| crowdsecurity/http-technology-probing | yes | yes |
| crowdsecurity/http-wordpress-scan | yes | yes |
| crowdsecurity/http-wordpress_user-enum | yes | yes |
| crowdsecurity/http-wordpress_wpconfig | yes | yes |
| crowdsecurity/http-xss-probbing | yes | yes |
| crowdsecurity/jira_cve-2021-26086 | yes | yes |
| crowdsecurity/netgear_rce | yes | yes |
| crowdsecurity/pulse-secure-sslvpn-cve-2019-11510 | yes | yes |
| crowdsecurity/spring4shell_cve-2022-22965 | yes | yes |
| crowdsecurity/thinkphp-cve-2018-20062 | yes | yes |
| crowdsecurity/vmware-cve-2022-22954 | yes | yes |
| crowdsecurity/vmware-vcenter-vmsa-2021-0027 | yes | yes |
| ltsich/http-w00tw00t | yes | yes |
