# 上流互換性（0.2.0）

上流の条件と辞書を使う検出を追加しました。固定したHTTP入力のテストでは一致しますが、上流製品全体についての完全互換を保証するものではありません。

## 変更

- RFC3164/RFC5424 syslog、Combined末尾の追加情報、NPMplus/Nginx Proxy Manager、Upsun journald、Apache/Nginx HTTPエラーを読みます。壊れた要求欄は原文として保持し、method/protocol/URLを推測しません。
- 同文のリクエストを数えます。完全同一ファイルの除外は`--dedup-files`でのみ有効です。これは上流と同じ観測件数を得るための既定動作変更です。
- Hubの59ルールに、元のID、filter、groupby、distinct、capacity、leakspeed、blackhole、cache_sizeを適用します。distinctはバケットの生存期間中保持し、overflowでリセットします。抑制されたoverflowでもバケットはリセットし、抑制期限は延長しません。
- 通常の減衰と、最終受付時刻から`(capacity+1)*leakspeed`を超えた期限切れを扱います。時刻順のHTTP入力について、CrowdSec forensicsの5,000イベントごとのunderflow GCを再現します。
- 辞書は同梱し、起動時に正規表現とJSONLを読みます。`LookupFile`のequals優先、最左contains、regexの順とタグも保持します。起動時や解析時の通信はありません。
- Auraの25パターンを弱めずに使用し、UA、危険メソッドも元の条件に合わせます。brute_force、enumeration_404、exfil_bytes、rare_user_agent、traffic_spikeを別のケース集計として実装しました。件数上限200/500/25と、母標準偏差・時刻バケットも原定義に合わせています。
- JSON/HTML/CSV/要約に互換検出を表示します。`upstream_alerts`はHub生アラート、`aura_matches`はAura条件のIP別集計、`aura_analysis`はケース集計です。`findings`はWebAudit独自の事案集約です。アラートと事案の件数は異なる概念です。JSONスキーマは`webaudit/2`に更新しました。

## 確認できた範囲

| 検証 | 結果 |
|---|---|
| HubのApache/Nginxを利用するシナリオケース | 60ケース |
| 原scenario.assertから抽出した生アラート | 100件一致 |
| 比較内容 | 元ルールID、IP、アラート数、イベント数、証拠順の要求・status・verb・log_type・args_len・IP・UA・host・sub_type・CVE/technologyタグ・確定タイムゾーンのtimestamp（2,052項目） |
| Aura原URLテスト | 31/31、タグ集合全体が一致（Pythonのtag_urlを参照実行） |
| Aura UA / 埋め込みログ文字列 | 3/3 UA判定、7/7構文受理結果が一致（ログは6件受理・1件拒否） |
| CrowdSec Goテスト等のHTTP文字列 | 有効HTTP 5/5を受理、壊れた1件・非HTTP syslog 2件を拒否。攻撃ラベル付きの評価ではありません |
| Hub入力全体の追加診断 | 81ケース991行中966行をHTTPとして解析。残る25行はNginx mail/stream記録で、HTTPとして解釈せず部分解析を表示 |
| 従来のアクセス形状による比較対象 | 935/935行を解析（旧版848/935） |

原ファイルとassertionは`audit/testdata/upstream`に保存しました。テストでは定義されたscenarioに絞って比較し、未設定の別ルールによる検出を誤検出として扱いません。攻撃の正解ラベルがないため、上記は互換性であり実環境の検知精度ではありません。`go test ./audit -run 'SourceGolden|Upstream|AuraSource' -count=1`で再検証できます。

従来の31/50という「別IDへの対応付け一致率」は、対象と比較方法が違うため100件の生アラート一致と直接の百分率比較はできません。今回は対応表を介さず原IDで比較しています。

## 入力時刻

タイムゾーンのないエラーログは`time/first/last=null`、`timezone_unknown=true`と壁時計を出力します。既定では別ファイルやUTCが確定したアクセス記録と時間的に混合しません。既知の設定がある場合は`--error-timezone Asia/Tokyo`や`--error-timezone UTC`を明示してください。指定は`error_timezone`に記録されます。

状態を持つHub検出には、ファイルをまたいだ時刻順が必要です。ファイル名順で読みます。時刻逆転を検出した場合は`partial=true`と警告を出します。上限に達した場合も部分解析を表示し、黙って互換と主張しません。夏時間の曖昧時刻や、ログ欠落をツールだけで解消することはできません。

## まだ保証していない範囲

- Magentoの4ルールはADMIN_LOGIN_FAILED/PAYMENT_FAILEDとASN/国情報が必要です。アクセスログから代用せず`upstream_rules[].supported=false`とします。
- Caddy、Envoy、Traefik、ALBなど別製品の取得形式、Nginx mail/stream、IIS、AppSec/body、上流のwhitelist/enrichment/postoverflow処理や任意の追加設定は対象外です。テスト選定に含まれていた別製品ケース11件は明示的にスキップし、ファイルと理由を残しています。
- AuraのElasticsearch実行環境は起動していません。Lucene regexpとPython/Go regexpの方言差、索引の切り詰め・mapping、分散terms集計、ESの同率順位やサンプル選択までの完全一致は未検証です。31件一致はPython側のURL判定についての結果です。IISの取り込みやUI/API互換も対象外です。
- Hubの未収録シナリオや将来の更新は、自動で互換になりません。現在の59ルール全てに上流のApache/Nginxアラートfixtureがあるわけではありません。個別の検証有無はrule-inventory.mdを参照してください。
- リソース上限、既知IPのみのオフライン解析、証拠保持上限を維持します。上流の無制限の状態保持や、運用設定の全組合せを再現するものではありません。

## 固定ソース

`audit/upstream/manifest.json`にAuraDFIR、CrowdSec、Hub、sec-listsのコミットと同梱ファイルのSHA-256があります。CIでハッシュとgoldenを確認します。アップデート時は元の期待値を書き換えて一致させるのではなく、新しい固定ソースに対する差分・辞書・ライセンスを確認し、同じ比較を繰り返してください。

## 最終検証と性能

`go test ./...`は176件成功（top level 55件、失敗0）。`go vet`、パーサfuzz、正規表現事前フィルターのRE2との差分fuzzが成功しました。新しいUA候補絞り込みは条件を変更せず、最終判定を元のRE2に任せます。記録は`measurements/upstream`、機械可読の互換検証概要は`compatibility.json`です。

| 入力 | 秒 | 行/秒 | 最大観測Goヒープbytes | 部分解析 |
|---|---:|---:|---:|---|
| 100,000行 / 11,001,390bytes | 18.22 | 5,489 | 6,410,712 | なし |
| 10,000行 / 31,090,135bytes | 4.00 | 2,502 | 7,959,104 | 長いUAの表示用サンプル切り詰めを明示 |
| 1,000,000行 / 3,111,013,890bytes | 338.08 | 2,958 | 12,290,256 | 長いUAの表示用サンプル切り詰めを明示 |

Windows amd64 / Go 1.27.4 / 24論理CPUでの単発測定です。全行を解析し、未解析0・重複除外0でした。Goヒープは10msサンプリングで、プロセス全メモリの厳密な最大ではありません。時刻・IP・パスのカーディナリティは固定しており、任意の実ログの速度や完全性を保証しません。GB級gzip、乱順、高カーディナリティの性能は未測定です。
