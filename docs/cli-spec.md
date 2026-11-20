# CLI contract

`webaudit INPUT... [-o PATH] [--format html|json|csv] [--verbose]`. Flags may precede or follow inputs. Default console summary; --format json/csv without -o writes machine report to stdout. -o defaults to HTML, creates a new file exclusively with mode 0600 and refuses overwrite/input collision. --format html without -o writes HTML to stdout. --log-regex accepts Go named groups ip,time,method,target,protocol,status,bytes,ua,referer,host. time is Apache time or RFC3339. No implicit XFF trust. Limits configurable via --max-line-bytes, --max-file-bytes, --max-keys, --max-findings. Exit 0 complete (findings allowed), 1 partial/failed read or exhausted analysis limits, 2 invocation error. Directory recursion ignores symlinks and selects .log/.log.N/.gz files. JSON has versioned schema and explicit nulls for unavailable fields; CSV includes metadata, incident and separate source detection records with details JSON. Schema is webaudit/2. --dedup-files explicitly excludes byte-identical complete files; repeated records remain. --error-timezone accepts a known IANA location for timezone-free HTTP error timestamps. No report files unless -o requested.

## GeoIP / ASN

`webaudit geoip download`で初回取得、`update`で版の確認と必要なDBだけ更新、`status`でオフライン整合性確認、`rollback`で保持した前世代をオフライン復元する。管理処理の成功/未導入statusは0、処理失敗/整合性失敗は1、サブコマンドの引数不正は2。

通常解析は管理DBをXDG/OSフォールバック保存先から自動検出する。明示の`--geoip-country PATH` / `--geoip-asn PATH`を最優先。管理DB未導入なら従来の実行ファイル相対geoipも検出する。壊れた管理DBは警告し自動GeoIPなしで解析、明示DBの不存在・破損・役割間違いは解析前に2で終了する。

通信はdownload/updateだけ。status/rollback/解析/レポート/整合性確認は通信しない。GeoIPが無効なら既存のJSON/CSV形式を維持して任意geoipを省略する。有効時は検索状態とDB公開版・取得・build日時、国/ASN別IP数、限定的な類似性を追加する。詳しくは[設計](geoip-design.md)と[DB管理](geoip-database-management.md)を参照。

GeoIPの自動検出時に使えないDBを無効化した場合は、他方のDBが利用できるかにかかわらず警告のみとし、その理由だけでは`partial`や終了コード1にしない。明示DBの検証失敗は引き続き2。有効なDBの解析中の検索失敗、GeoIP peer保持上限超過は集計の不完全性として`partial`と終了コード1に反映する。

`-o`で新規作成したレポートの書き込みまたはcloseに失敗した場合は、不完全なファイルの削除を試みて1で終了する。削除にも失敗した場合はそのエラーも通知する。レポート保存後のstdout要約出力だけが失敗した場合は、保存済みレポートを保持する。プロセス強制終了や電源断による中断時の削除は保証しない。
