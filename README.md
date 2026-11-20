# WebAudit

Apache HTTP Server / Nginx の既存アクセスログから、不審なアクセス、関連事案、成否の推定と追加調査事項を得るオフラインCLIです。Go標準ライブラリだけで動作し、DB・CrowdSec・Docker・APIキー・設定ファイル・管理者権限を必要としません。実行中のネットワーク通信はありません。

**アクセスログは攻撃の試行を示しても、侵害成功を確定できるとは限りません。** HTTP 200・302・500だけでは成功と判定しません。本文やアプリケーションの証拠が不足する場合は、成否不明を返します。

## 配布・ビルド

対象はWindows / Linux、amd64です。`dist/webaudit-windows-amd64.exe` または `dist/webaudit-linux-amd64` を任意の場所に置いて実行します。Linuxでは必要に応じて `chmod +x webaudit-linux-amd64` を実行してください。公開Releaseの配布は行っていません。

開発環境はGo 1.27.4。公式の安定版情報とSHA-256を確認して選定しました。外部Goモジュールの依存はありません。

```sh
go test ./...
go vet ./...
go build -trimpath -buildvcs=false -o dist/webaudit ./cmd/webaudit
```

Windowsでのビルド例:

```powershell
go build -trimpath -buildvcs=false -o dist/webaudit-windows-amd64.exe ./cmd/webaudit
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -buildvcs=false -o dist/webaudit-linux-amd64 ./cmd/webaudit
```

## 基本操作

以下の `webaudit` を、配置した実行ファイルのパスに読み替えてください。

```sh
webaudit access.log
webaudit ./logs/
webaudit ./logs/ -o report.html
webaudit access.log access.log.1.gz
webaudit ./logs/ --format json
webaudit ./logs/ --format csv
webaudit ./logs/ --verbose
webaudit access.log --format json -o report.json
```

既定では標準出力に要約と上位5事案を表示し、ファイルは作成しません。`--format json/csv/html` を単独指定すると、その形式を標準出力に出力します。`-o` 指定時はファイルに出力し、標準出力に要約を表示します。`-o` の既定形式はHTMLです。既存の出力や元ログを上書きしません。`--verbose` はファイル別の診断を標準エラーへ出力します。

JSONは `webaudit/2` スキーマで、欠損した任意項目は `null` です。CSVはmetadata・incident・Hub/Aura検出行を持ち、`details_json` に完全な構造を格納します。CSVセルの数式実行を抑止するため、危険な先頭文字には引用符を付けます。HTMLは単一ファイルで、外部画像・CDN・スクリプトを使いません。証拠ログはHTMLとして実行されないようエスケープします。

終了コードは0: 解析完了、1: 読み込みエラー・解析不能行・解析上限等による部分解析、2: 引数不正または出力先エラーです。検知があるだけでは異常終了になりません。

## 入力形式

- Apache Common / Combined、Nginx標準Combined。
- 先頭にvhostを付加したCommon / Combined。RFC3164 / RFC5424 syslogラッパー、NPMplus、Combinedに続く追加フィールド、Upsun journaldラッパー。
- クライアントIP・時刻・HTTP要求を含むApache/Nginxエラーログ。タイムゾーンがない時刻は確定UTCとして出力せず、ファイル内の壁時計で互換検出を行います。既知の設定がある場合は`--error-timezone Asia/Tokyo`等を指定します。
- Nginx JSON: `remote_addr`, `time_local` または `time_iso8601`, `request`, `status`, `body_bytes_sent`, `http_user_agent`, `http_referer`, `host` の明示的なキー。重複キーや時刻キーの競合は拒否します。
- 複数ファイル、ローテーションファイル、gzip（拡張子ではなくマジックで判定）。ディレクトリは再帰的に `.log`, `.log.N`, `.gz`, `access`, `access.N` を選択します。その他の名前はファイルを直接指定してください。

追加フィールドは未対応の末尾情報として原文を保持し、XFFなどの意味を推測しません。任意のLogFormatには `--log-regex` でGoの名前付きグループを指定します。必須は `ip`, `time`, `target`。任意で `method`, `protocol`, `status`, `bytes`, `ua`, `referer`, `host` を指定できます。時刻はApache形式またはRFC3339です。

```sh
webaudit custom.log --log-regex '^(?P<ip>\S+) (?P<time>\S+) (?P<target>\S+)$'
```

X-Forwarded-Forを実クライアントIPとして採用しません。記録された接続元がプロキシの場合、利用者の特定はできません。ホスト名だけのクライアント欄、必須IP・時刻がない行、任意のWAF形式は解析対象外です。壊れたHTTP要求は生の要求欄を保持し、正常なmethod/URL/protocolを捏造しません。

## 上流互換の検出

0.2.0では、固定したHub/CrowdSecソースのHTTPルール59件と辞書、およびAuraの25シグネチャ・UA・メソッド・ケース集計条件を追加しました。Hubは元のルールID、減衰、distinct、groupby、blackhole、証拠キャッシュ上限を使用します。`upstream_alerts`、`aura_matches`、`aura_analysis`に記録し、独自の`findings`と別に表示します。

同一内容のアクセスも実際の観測として数えます。内容が完全一致する重複ファイルだけを除外したい場合は`--dedup-files`を明示してください。同じファイルパスを重ねて指定した場合は一度だけ読みます。

上流テストでの検証範囲、固定コミット、Elasticsearch実行系や製品固有ログなど完全一致を保証できない範囲は[上流互換性](docs/upstream-compatibility.md)を参照してください。未評価ルールは`upstream_rules[].supported=false`で示します。

## 検知と成否判定

L1は28個の埋め込みJSONルールです。SQLi / NoSQLi、XSS、OSコマンド、RCE関連ペイロード、Shellshock、SSTI、LDAP / XPath、パストラバーサル / LFI / RFI、SSRF、URLに現れるXXE、デシリアライズ、Log4Shell、Spring4Shell、Struts、CRLF、機密ファイル、WebShell、選択したCVE探索、IIS、null byte、スキャナーUA、不審メソッド・HTTPバージョンに対応します。

通常の `/admin` や `/wp-admin/` への単発アクセスだけでは警告しません。管理画面を含む多数のURLへのエラーを伴う探索はL2で検知します。独自の事案検出ではcurl、python-requests、通常クローラーという名前だけでは警告しません。互換用のAura/Hub検出には上流のUA条件をそのまま適用するため、結果が出る場合があります。

L2は9種類の時間窓・頻度・探索分析、L3は5種類の統計候補です。L4はIP・ホスト・UA・技法の系統・時間区間を使って関連付けの仮説を記録します。L5は以下を区別します。

| 値 | 意味 |
|---|---|
| confirmed_success | 成功を裏付ける証拠あり（アクセスログのみの初期版では出力しない） |
| possible_success | 成功の疑い。機密リソースへのブロック後、同一リソースで非空2xxが反復した場合等。内容確認が必要 |
| unknown | 成否不明。既定の判断 |
| likely_failed | 失敗の疑い。事案内の全観測が403/404で、3観測以上の場合。失敗の断定ではない |
| confirmed_failure | 失敗を裏付ける証拠あり（アクセスログのみの初期版では出力しない） |

攻撃らしさのスコアは一意ルールの重要度を合計し100で打ち切ります。成否の確信度とは独立です。確信度は校正された確率ではなく、証拠強度の説明値です。判定には理由、元ファイル・行番号、正規化履歴、不足情報、追加調査事項を付けます。

## オプションと資源上限

| オプション | 既定値・動作 |
|---|---|
| `-o PATH` | 明示指定時だけ新規レポート作成。既存パスは拒否 |
| `--format html/json/csv` | 未指定なら要約（`-o` 使用時はHTML） |
| `--verbose` | ファイル別診断 |
| `--log-regex REGEX` | 明示的なカスタム形式 |
| `--max-line-bytes` | 65536。巨大行を破棄して次行へ進む |
| `--max-file-bytes` | 8589934592。ファイルごとの展開後上限 |
| `--max-keys` | 4096。各解析表・入力ファイル選択の上限 |
| `--max-findings` | 2000。事案・中間シグナルそれぞれの上限 |
| `--max-evidence-bytes` | 33554432。事案に保持する証拠文字列の合計上限。プロセス全体のメモリ上限ではない |
| `--version`, `--help` | バージョン、使用方法 |

ストリーミングで処理し、gzipをディスクへ展開しません。事案ごとの証拠は最大8件、元ログ文字列は最大4096bytes、UA等にも個別上限があります。切り詰めはフラグで示し、完全な内容は元ログの行を参照します。異なる値の集合は64件で打ち切ります。上限時は警告と部分解析状態を出し、検出漏れの可能性を開示します。結果の機密性は元ログと同様に扱ってください。WindowsのファイルACLは配置先の継承設定にも依存します。

## 検証と既知の制約

精度・性能・テスト結果は [検証レポート](docs/validation.md)、[精度評価](docs/accuracy.md)、[性能測定](docs/performance.md) を参照してください。[合成サンプルHTML](examples/sample-report.html) と [サンプルログ](examples/sample.log) も含めています。

時間窓は150秒ずらした2つの5分区間です。厳密な全時点のローリング窓ではありません。順序が前後するログは保持上限内で集計できますが、オンライン応答サイズの基準値とLeaky Bucketは順序の影響を受けます。任意順序の全件外部ソートは行いません。同一行も反復リクエストとして保持します。互換検出の状態は上流の各ルール固有の減衰・distinct・抑制期間を使い、乱順時は部分解析とします。

URLの復号は最大2回、ケース・区切り・queryの `+`、ログの `\xNN` を検知用の候補として扱います。アプリケーションの解釈と同一であるとは保証しません。任意のUnicode正規化、`%uNNNN`、無制限の多重復号には対応しません。本文だけの攻撃、未収録CVE、実際の応答内容・認証結果・ファイル改ざんは確認できません。正常な高頻度APIも頻度異常の調査候補になり得ます。実ログでの検証は未実施です。

開発用評価:

```sh
go run ./tools/evaluate
go run ./tools/benchmark -lines 1000000
go run ./tools/benchmark -lines 1000000 -padding 3000
go test ./audit -run='^$' -fuzz=FuzzParse -fuzztime=10s -parallel=4
```

## 出典とライセンス

WebAuditはMIT。AuraDFIR、CrowdSec、CrowdSec Hubを参照して独立実装しました。[出典・ライセンス表示](THIRD_PARTY_NOTICES.md)、[競合調査](docs/competitor-analysis.md)、[ルール台帳](docs/rule-inventory.md)、[検知設計](docs/detection-design.md)、[対応範囲](docs/detection-coverage.md) を参照してください。外部データリストは無条件に移植せず、未対応の理由を台帳に記録しています。
