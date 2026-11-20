# CLI contract

`webaudit INPUT... [-o PATH] [--format html|json|csv] [--verbose]`. Flags may precede or follow inputs. Default console summary; --format json/csv without -o writes machine report to stdout. -o defaults to HTML, creates a new file exclusively with mode 0600 and refuses overwrite/input collision. --format html without -o writes HTML to stdout. --log-regex accepts Go named groups ip,time,method,target,protocol,status,bytes,ua,referer,host. time is Apache time or RFC3339. No implicit XFF trust. Limits configurable via --max-line-bytes, --max-file-bytes, --max-keys, --max-findings. Exit 0 complete (findings allowed), 1 partial/failed read or exhausted analysis limits, 2 invocation error. Directory recursion ignores symlinks and selects .log/.log.N/.gz files. JSON has versioned schema and explicit nulls for unavailable fields; CSV includes metadata, incident and separate source detection records with details JSON. Schema is webaudit/2. --dedup-files explicitly excludes byte-identical complete files; repeated records remain. --error-timezone accepts a known IANA location for timezone-free HTTP error timestamps. No report files unless -o requested.

## GeoIP / ASN追加

`--geoip-country PATH`と`--geoip-asn PATH`でローカルMMDBを任意指定。実行ファイル相対の`geoip/`から役割ごとに自動検出し、明示指定を優先する。未設定は従来の出力形式、明示したDBの不存在・破損は終了コード2。詳しくは[GeoIP設計](geoip.md)を参照。
