# WebAudit

Apache HTTP Server / Nginx のログから、不審なアクセスと関連する事案を見つけ、攻撃の成否の推定や追加調査事項を確認するためのオフラインCLIです。

実行ファイルとログがあれば使えます。Go・DB・CrowdSec・Docker・APIキー・設定ファイル・管理者権限は不要で、解析中にネットワーク通信は行いません。

**アクセスログだけで侵害の成功を確定できるとは限りません。** HTTP 200・302・500だけでは成功と判定せず、証拠が不足する場合は「成否不明」とします。

## はじめに：ログを解析してHTMLレポートを開く

### 1. 実行ファイルをダウンロードする

[GitHub Releases](https://github.com/mikoto2000/webaudit/releases)から、お使いのOSとCPUに合うファイルを取得してください。配布対象はWindows / Linux / macOSのamd64（x86-64）・arm64（ARM64）です。リリースごとの添付ファイルを確認してください。

| 環境 | ダウンロードするファイル |
|---|---|
| Windows（x86-64） | `webaudit-windows-amd64.exe` |
| Windows（ARM64） | `webaudit-windows-arm64.exe` |
| Linux（x86-64） | `webaudit-linux-amd64` |
| Linux（ARM64） | `webaudit-linux-arm64` |
| macOS（Intel） | `webaudit-darwin-amd64` |
| macOS（Apple Silicon） | `webaudit-darwin-arm64` |

### 2. ログを指定して実行する

ダウンロードした実行ファイルと解析する `access.log` を同じフォルダーに置き、そのフォルダーでターミナルを開いて実行します。ログが別の場所にある場合は、`access.log` を実際のパスに置き換えてください。空白を含むパスは引用符で囲みます。

**Windows（PowerShell）**

```powershell
.\webaudit-windows-amd64.exe .\access.log -o .\report.html
```

**Linux**

```sh
chmod +x ./webaudit-linux-amd64
./webaudit-linux-amd64 ./access.log -o ./report.html
```

**macOS（Apple Silicon）**

```sh
chmod +x ./webaudit-darwin-arm64
./webaudit-darwin-arm64 ./access.log -o ./report.html
```

Windows / LinuxのARM64環境では、例のファイル名の `amd64` を `arm64` に置き換えてください。Intel Macでは `webaudit-darwin-amd64` を使います。

元のログは変更しません。`report.html` がすでにある場合は上書きせず終了するため、別の出力名を指定してください。

手元にログがない場合は、[サンプルログ](examples/sample.log)を保存して入力に指定できます。リポジトリを取得済みの場合は `examples/sample.log` を指定してください。[生成済みのサンプルHTML](examples/sample-report.html)も保存してブラウザーで開けます。いずれも合成データによるデモです。

### 3. 結果を確認する

端末には解析件数・上位5事案・警告が表示されます。生成された `report.html` をブラウザーで開くと、保持された事案の証拠や判定理由を確認できます。HTMLは単一ファイルで、外部画像・CDN・スクリプトを使いません。

まず次の順に確認してください。

1. **解析の状態と警告**：`Analysis partial` や `Warnings` がある場合は、読み込めなかったログや解析上限を確認します。`--verbose` を付けるとファイル別の診断も得られます。
2. **不審な事案と証拠**：送信元IP、技法、観測数、元ファイル・行番号を確認し、必要に応じて元ログを調べます。
3. **成否判定と追加調査事項**：判定理由と不足情報を読み、アプリケーションのログや応答内容などと照合します。

| 成否判定 | 読み方 |
|---|---|
| `possible_success` | 成功の疑い。例：機密リソースへのブロック後、同一リソースで非空2xxが反復。内容確認が必要 |
| `unknown` | 成否不明。既定の判断 |
| `likely_failed` | 失敗の疑い。事案内の全観測が403/404で、3観測以上の場合。失敗の断定ではない |
| `confirmed_success` / `confirmed_failure` | 成功・失敗を裏付ける証拠あり。アクセスログのみの現行版では出力しない |

攻撃らしさのスコアと成否の確信度は別の値です。スコアは一意ルールの重要度の合計を100で打ち切り、確信度は校正された確率ではなく証拠強度を説明します。判定には理由、正規化履歴、不足情報、追加調査事項を付けます。

独自の事案が0件でも、Hub / Aura由来の検出は別に表示されます。警告と解析範囲も併せて確認してください。

## よく使う操作

以降の例の `webaudit` は、ダウンロードした実行ファイルのパスに置き換えてください。例：Windows x86-64では `.\webaudit-windows-amd64.exe`、Linux x86-64では `./webaudit-linux-amd64`、Apple SiliconのMacでは `./webaudit-darwin-arm64` です。

### 画面の要約だけで確認する

```sh
webaudit access.log
```

`-o` を省略すると、ファイルを作成せず要約と上位5事案を表示します。

### フォルダーやローテーション済みログをまとめて調べる

```sh
# フォルダーを再帰的に解析し、HTMLに保存する
webaudit ./logs/ -o report.html

# 複数ファイルをまとめて解析する（gzipは展開不要）
webaudit access.log access.log.1.gz -o rotated-report.html
```

フォルダー指定では `.log`, `.log.N`, `.gz`, `access`, `access.N` を選びます。それ以外の名前はファイルを直接指定してください。

複数ファイルはパスの辞書順で読み込みます。引数の順番を変えても読み込み順は変わりません。ローテーション済みログなどで時刻が前後すると一部の検出に影響し、互換検出では部分解析となる場合があります。出力の `Warnings` も確認してください。

同一内容のアクセスも実際の観測として数えます。内容が完全一致する重複ファイルだけを除外したい場合は`--dedup-files`を明示してください。同じファイルパスを重ねて指定した場合は一度だけ読みます。

### JSON / CSVに保存する

```sh
# 別のツールで処理するためのJSON
webaudit access.log --format json -o report.json

# 表計算ソフトなどで確認するためのCSV
webaudit access.log --format csv -o report.csv
```

`-o` を付けると指定ファイルに保存し、端末には要約を表示します。`--format` を省略した場合の保存形式はHTMLです。JSON / CSVで保存する場合は、上の例のように `--format` も指定してください。

ファイルに保存せず別のコマンドに渡す場合は、`-o` を省略します。

```sh
webaudit access.log --format json
```

`--format html/json/csv` だけを指定した場合は、その形式を標準出力に出力します。

## 対応するログ形式

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

## 解析できない・結果が一部しか出ない場合

まず `--verbose` を付けて、ファイルごとの解析件数とエラーを確認してください。

```sh
webaudit ./logs/ --verbose
```

| 状況 | 確認すること |
|---|---|
| フォルダー内のログが選ばれない | 対象の拡張子・名前かを確認する。対象外の名前ならファイルを直接指定する |
| `Unparsed` がある | 対応するログ形式か、必須のIP・時刻が含まれるかを確認する。カスタム形式には `--log-regex` を使う |
| `Analysis partial` が出る | `Warnings` とファイル別診断を確認する。入力エラーのほか、解析上限や互換検出での時刻順序の影響も確認する |
| 出力ファイルを作成できない | 出力先フォルダーが存在して書き込み可能か、同名のファイルがないかを確認する |

終了コードは以下のとおりです。検知があるだけでは異常終了になりません。

| 終了コード | 意味 |
|---|---|
| `0` | 解析完了 |
| `1` | 入力エラー・解析不能行・解析上限等による部分解析、またはレポート書き込み失敗 |
| `2` | 引数不正、出力先の事前確認・ファイル作成エラー、明示したGeoIP DBのエラーなど |

## 国・ASN情報を追加する（任意）

通常の解析にGeoIP DBは不要です。送信元IPの国やASN（ネットワークの識別番号）を調査の補助情報として表示したい場合に設定します。

```sh
webaudit access.log --geoip-country ./country.mmdb --geoip-asn ./asn.mmdb
```

国・ASNの情報が必要な場合は、DB-IP LiteのCountry / ASN MMDBを別途準備してください。DBは取得・展開して配置し、実行ファイルには同梱しません。解析中のダウンロード・外部API・DNS検索はありません。Countryだけ、ASNだけでも動作します。

明示指定を優先し、未指定の役割は実行ファイルと同じ場所の`geoip/country.mmdb`・`geoip/asn.mmdb`を探します。固定名がなければ`geoip/dbip-country-lite-YYYY-MM.mmdb`・`geoip/dbip-asn-lite-YYYY-MM.mmdb`の辞書順で最後を選びます。カレントディレクトリは探索しません。DBがなければ従来どおり動作し、GeoIP出力項目も追加しません。明示DBの不存在・破損は解析開始前に終了コード2、破損した自動検出DBは警告して継続します。

国コード・英語の国名・ASN番号・組織名、DB提供元・使用パス・種類・MMDBのbuild_epochによるUTC更新日を出力します。不明はJSONの`null`、画面では`unknown`です。IPv4/IPv6に対応し、IPv4 mapped IPv6は正規化します。private / loopback / link_local / shared / multicast / unspecified / reserved / invalidを区別し、公開IPだけをMMDB検索します。特殊用途範囲は保守的に除外します。

国別・ASN別の既存WebAudit事案数・技法、ASNに属する複数の不審IP、通常アクセスを含むASN別リクエスト集中を調査用に表示します。同じ国・ASNだけでは同一攻撃者と推定せず、危険度・事案の統合・成否・確信度は変更しません。上流検出は既存の別集計を維持します。

JSONは任意の`geoip`ブロックと各事案の`geoip`を追加します。CSVは既存列を維持し、metadata / incidentの`details_json`に格納します。CLIは上位5群・5 IP、HTMLは保持した全群・IPを表示します。DB-IPの出典・ライセンスリンクもHTMLに記録します。

LRUはヒット・未収録結果ともIP単位で最大`--max-keys`件。リクエスト集計のIP保持も同じ上限で、超過時は部分解析と件数の下限を明示します。群ごとのIP・技法サンプルは64件までです。MMDBはメモリマップするため、キャッシュ以外にDBサイズに応じたアドレス空間・ページキャッシュを使用します。解析中はDBファイルを変更・切り詰めず、更新版は次回解析から使ってください。

調査・設計・検証の詳細は[GeoIP設計と検証](docs/geoip.md)、ライセンス全文は[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)を参照してください。

## オプションと資源上限

利用できるオプションは `webaudit --help`、バージョンは `webaudit --version` でも確認できます。

| オプション | 既定値・動作 |
|---|---|
| `-o PATH` | 明示指定時だけ新規レポート作成。既存パスは拒否 |
| `--format html/json/csv` | 未指定なら要約（`-o` 使用時はHTML） |
| `--verbose` | ファイル別診断 |
| `--log-regex REGEX` | 明示的なカスタム形式 |
| `--error-timezone ZONE` | エラーログのタイムゾーン（例: `Asia/Tokyo`） |
| `--dedup-files` | 内容が完全一致する入力ファイルを除外 |
| `--geoip-country PATH`, `--geoip-asn PATH` | ローカルのCountry / ASN MMDBを指定 |
| `--max-line-bytes` | 65536。巨大行を破棄して次行へ進む |
| `--max-file-bytes` | 8589934592。ファイルごとの展開後上限 |
| `--max-keys` | 4096。各解析表・入力ファイル選択の上限 |
| `--max-findings` | 2000。事案・中間シグナルそれぞれの上限 |
| `--max-evidence-bytes` | 33554432。事案に保持する証拠文字列の合計上限。プロセス全体のメモリ上限ではない |
| `--version`, `--help` | バージョン、使用方法 |

ストリーミングで処理し、gzipをディスクへ展開しません。事案ごとの証拠は最大8件、元ログ文字列は最大4096bytes、UA等にも個別上限があります。切り詰めはフラグで示し、完全な内容は元ログの行を参照します。異なる値の集合は64件で打ち切ります。上限時は警告と部分解析状態を出し、検出漏れの可能性を開示します。結果の機密性は元ログと同様に扱ってください。WindowsのファイルACLは配置先の継承設定にも依存します。

## 検知の詳細と制約

### WebAudit独自の検知

L1は28個の埋め込みJSONルールです。SQLi / NoSQLi、XSS、OSコマンド、RCE関連ペイロード、Shellshock、SSTI、LDAP / XPath、パストラバーサル / LFI / RFI、SSRF、URLに現れるXXE、デシリアライズ、Log4Shell、Spring4Shell、Struts、CRLF、機密ファイル、WebShell、選択したCVE探索、IIS、null byte、スキャナーUA、不審メソッド・HTTPバージョンに対応します。

通常の `/admin` や `/wp-admin/` への単発アクセスだけでは警告しません。管理画面を含む多数のURLへのエラーを伴う探索はL2で検知します。独自の事案検出ではcurl、python-requests、通常クローラーという名前だけでは警告しません。互換用のAura/Hub検出には上流のUA条件をそのまま適用するため、結果が出る場合があります。

L2は9種類の時間窓・頻度・探索分析、L3は5種類の統計候補です。L4はIP・ホスト・UA・技法の系統・時間区間を使って関連付けの仮説を記録します。成否判定の読み方は「結果を確認する」を参照してください。

### Hub / Aura由来の検出

固定したHub/CrowdSecソースのHTTPルール59件と辞書、およびAuraの25シグネチャ・UA・メソッド・ケース集計条件に対応しています。Hubは元のルールID、減衰、distinct、groupby、blackhole、証拠キャッシュ上限を使用します。`upstream_alerts`、`aura_matches`、`aura_analysis`に記録し、独自の`findings`と別に表示します。

上流テストでの検証範囲、固定コミット、Elasticsearch実行系や製品固有ログなど完全一致を保証できない範囲は[上流互換性](docs/upstream-compatibility.md)を参照してください。未評価ルールは`upstream_rules[].supported=false`で示します。

### 既知の制約

時間窓は150秒ずらした2つの5分区間です。厳密な全時点のローリング窓ではありません。順序が前後するログは保持上限内で集計できますが、オンライン応答サイズの基準値とLeaky Bucketは順序の影響を受けます。任意順序の全件外部ソートは行いません。同一行も反復リクエストとして保持します。互換検出の状態は上流の各ルール固有の減衰・distinct・抑制期間を使い、乱順時は部分解析とします。

URLの復号は最大2回、ケース・区切り・queryの `+`、ログの `\xNN` を検知用の候補として扱います。アプリケーションの解釈と同一であるとは保証しません。任意のUnicode正規化、`%uNNNN`、無制限の多重復号には対応しません。本文だけの攻撃、未収録CVE、実際の応答内容・認証結果・ファイル改ざんは確認できません。正常な高頻度APIも頻度異常の調査候補になり得ます。実ログでの検証は未実施です。

### 出力形式の詳細

JSONは `webaudit/2` スキーマで、欠損した任意項目は `null` です。CSVはmetadata・incident・Hub/Aura検出行を持ち、`details_json` に完全な構造を格納します。CSVセルの数式実行を抑止するため、危険な先頭文字には引用符を付けます。HTMLの証拠ログは、HTMLとして実行されないようエスケープします。

## 関連資料・開発

- [検証レポート](docs/validation.md)、[精度評価](docs/accuracy.md)、[性能測定](docs/performance.md)：検証方法と結果
- [検知の対応範囲](docs/detection-coverage.md)：対応する技法と検出範囲
- [上流互換性](docs/upstream-compatibility.md)：Hub / Auraとの互換範囲
- [開発者向けガイド](DEVELOPMENT.md)：開発環境、ビルド・テスト・評価、リリース手順

## 出典とライセンス

WebAuditは[MIT License](LICENSE)です。AuraDFIR、CrowdSec、CrowdSec Hubを参照して独立実装しました。依存ライブラリや参照元の表示は[出典・ライセンス表示](THIRD_PARTY_NOTICES.md)を参照してください。
