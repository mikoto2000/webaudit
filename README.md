# WebAudit

Apache HTTP Server / Nginx のログから、不審なアクセスと関連する事案を見つけ、攻撃の成否の推定や追加調査事項を確認するためのオフラインCLIです。

実行ファイルとログがあれば使えます。Go・DB・CrowdSec・Docker・APIキー・設定ファイル・管理者権限は不要で、解析中にネットワーク通信は行いません。

**アクセスログだけで侵害の成功を確定できるとは限りません。** HTTP 200・302・500だけでは成功と判定せず、証拠が不足する場合は「成否不明」とします。

v2.0.2では11章構成の日英調査報告書、全件証跡・統計・調査カバレッジの別紙、原本と成果物のハッシュ、解析中の進捗表示を追加しました。変更点は[v2.0.2リリースノート](docs/releases/v2.0.2.md)を参照してください。既存のバッチ解析・リアルタイム監視・状態復元・外部コマンドHookも引き続き利用できます。GeoIP / ASNデータベースの初回導入と更新は[GeoIPデータベース管理](docs/geoip-database-management.md)を参照してください。

## はじめに：ログを解析してHTMLレポートを開く

継続監視には明示的に `watch` を指定します。従来の一括解析はそのまま利用できます。

```sh
webaudit watch /var/log/nginx/access.log
webaudit watch /var/log/nginx/ --from beginning --format jsonl
webaudit watch access.log --on-detect ./examples/notify.sh
webaudit watch access.log --on-detect ./examples/notify.sh --on-detect-event all
webaudit watch access.log --no-state
```

初回は末尾から開始し、`--from beginning` で既存内容も読み取ります。保存済み状態があれば
`--from` より優先します。`--reset-state --from beginning` で明示的に読み直せます。
`Ctrl+C` で状態を保存して終了します。通常監視に設定ファイル、外部DB、デーモン、ネットワークは不要です。
Hookは指定時だけ、同じOSユーザーで実行します。

対応ログ、ファイル選択、ローテーション、JSONLスキーマ、状態管理、Hook設定と制限事項は
[監視・Hookガイド](docs/watch.md)、実行例は[watch examples](examples/watch-examples.md)、
試験と実測値は[検証記録](docs/watch-validation.md)を参照してください。

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

配布ファイルと同じリリースに`SHA256SUMS.txt`、`LICENSE`、`THIRD_PARTY_NOTICES.md`も添付しています。取得したバイナリのSHA-256を一覧と照合できます。

| 環境 | SHA-256を表示するコマンド |
|---|---|
| Windows（PowerShell） | `Get-FileHash .\webaudit-windows-amd64.exe -Algorithm SHA256` |
| Linux | `sha256sum ./webaudit-linux-amd64` |
| macOS | `shasum -a 256 ./webaudit-darwin-arm64` |

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

HTMLのWebAudit事案と独立したHub・Auraの検出は、一覧表のリンクから各詳細へ移動でき、詳細の末尾から一覧表に戻れます。Hub・Auraの詳細には生ログを最大8件、1件あたり4096バイトまで表示します。Auraの集計検出は、その集計対象に属するログの例です。生ログはHTML出力時のみ解析中に保持し、合計保持量は独自事案の証拠とは別枠で `--max-evidence-bytes` を上限とします。省略時は警告を表示します。

HTMLの事案詳細には、攻撃・検出の種類ごとに「不明な理由」「確認する場所」「何が見つかれば判断できるか」を選択した言語で表示します（既定は日本語）。SQLインジェクション、コマンド実行、機密ファイル、XSS、認証試行、大量アクセスなどに応じ、成功・失敗を裏付ける証拠の例を案内します。複数の種類を検出した事案では、それぞれの案内を表示します。成功・失敗の疑いにも確定に必要な確認案内を付けます。端末の上位5事案にも表示し、JSONでは各事案の `outcome.investigation`、CSVでは `details_json` に含めます。Hub / Aura由来の別枠の検出にはこの案内を付けません。

案内は追加調査の目安であり、証拠を検出したという意味ではありません。時刻・タイムゾーン・対象ホスト・URL、可能ならリクエストIDで当時の記録を照合してください。ログに痕跡がないだけでは失敗と判断できず、記録が残っていない場合は成否不明が続きます。失敗の証拠は確認できた要求の範囲に限られます。現在の環境での再現結果だけでは当時の成否を確定できません。追加証拠を取り込んで自動的に判定を更新する機能はありません。

独自の事案が0件でも、Hub / Aura由来の検出は別に表示されます。警告と解析範囲も併せて確認してください。

## よく使う操作

以降の例の `webaudit` は、ダウンロードした実行ファイルのパスに置き換えてください。例：Windows x86-64では `.\webaudit-windows-amd64.exe`、Linux x86-64では `./webaudit-linux-amd64`、Apple SiliconのMacでは `./webaudit-darwin-arm64` です。

### HTMLレポートの言語を選ぶ

HTMLレポートは既定で日本語です。`--lang ja` / `--lang en` で、見出し・成否判定名・判定理由・不足情報・攻撃別の確認案内・警告・GeoIPの説明など、WebAuditが表示する文言を切り替えられます。

```sh
webaudit access.log -o report-ja.html             # 既定は日本語
webaudit access.log --lang ja -o report-ja2.html   # 日本語を明示
webaudit access.log --lang en -o report-en.html    # 英語
webaudit access.log --format html --lang en       # 英語HTMLを標準出力へ
```

指定できる値は小文字の`ja`と`en`だけです。それ以外や空の値は、解析・ファイル作成前に引数エラー（終了コード2）になります。従来の単一ファイル出力では`--lang`はHTMLに適用し、端末の要約・ヘルプ・JSON・CSVの内容は変更しません。報告書一式では共通モデルの説明文にも適用します。JSON・CSVのキーや判定コードも維持します。

元ログ、URL、IP、ホスト名、User-Agent、ルールID、DBに記録された国名・組織名などは原文を保持します。ライセンス本文とOS・外部ライブラリ由来の診断の詳細も原文のままです。日本語HTMLでは診断の原文であることを示します。

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

LB配下では、Apache／Nginx側で信頼するLBから実クライアントIPを復元し、解析対象のIP欄に記録してください。[LB配下での設定・動作確認・IP集計への影響](docs/load-balancer.md)に、XFFとPROXY protocolの設定例を掲載しています。WebAudit自身がLB構成を推定したり、転送ヘッダーを検証してIPを置き換えたりする機能はありません。

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
webaudit geoip download
webaudit access.log -o report.html
webaudit geoip update
webaudit geoip status
```

手持ちのDBを使う場合は個別に指定できます。

```sh
webaudit access.log --geoip-country ./country.mmdb --geoip-asn ./asn.mmdb
```

初回は`webaudit geoip download`だけでDB-IP LiteのCountry / ASNを取得できます。更新は`webaudit geoip update`、確認は`webaudit geoip status`です。updateは未導入なら初回取得します。管理者権限は不要です。DBは実行ファイルに同梱せず、解析中のダウンロード・外部API・DNS検索はありません。

保存先は有効な絶対`XDG_DATA_HOME/webaudit/geoip/`、未設定・空・相対パスの場合はLinux/macOSで`~/.local/share/webaudit/geoip/`、Windowsで`%LOCALAPPDATA%\webaudit\geoip\`です。WindowsのLOCALAPPDATAフォールバックはWebAudit独自規約です。内部の世代やファイル名を利用者が管理する必要はありません。

保存したDBは通常の`webaudit access.log`で自動利用します。明示指定を最優先し、残りの役割は管理DBを使います。管理DBが未導入の場合だけ、従来どおり実行ファイルと同じ場所の`geoip/country.mmdb`・`geoip/asn.mmdb`を探します。固定名がなければ`geoip/dbip-country-lite-YYYY-MM.mmdb`・`geoip/dbip-asn-lite-YYYY-MM.mmdb`の辞書順で最後を選びます。カレントディレクトリは探索しません。DBがなければ従来どおり動作し、GeoIP出力項目も追加しません。明示DBの不存在・破損は解析開始前に終了コード2、破損した管理DBは警告し、自動GeoIPを無効にして解析を継続します。必要に応じて`webaudit geoip rollback`で保持した前世代を復元できます。

国コード・英語の国名・ASN番号・組織名、DB提供元・使用パス・種類・MMDBのbuild_epochによるUTC更新日を出力します。不明はJSONの`null`、画面では`unknown`です。IPv4/IPv6に対応し、IPv4 mapped IPv6は正規化します。private / loopback / link_local / shared / multicast / unspecified / reserved / invalidを区別し、公開IPだけをMMDB検索します。特殊用途範囲は保守的に除外します。

国別・ASN別の既存WebAudit事案数・異なる発信元IP数・技法、ASNに属する複数の不審IP、通常アクセスを含むASN別リクエスト集中を調査用に表示します。同じ国・ASNだけでは同一攻撃者と推定せず、危険度・事案の統合・成否・確信度は変更しません。上流検出は既存の別集計を維持します。同じ既知ASNに加えて要求先パス・技法・5分区間が一致する複数IPの事案には、参照付きの類似性ヒントを表示します。対象hostが不明なら同一サーバーとは確認できません。

検索状態は`found` / `not_found` / `non_public` / `invalid_ip` / `db_not_installed` / `read_error`を区別し、CountryとASNごとの状態も保持します。管理DBの実際の公開版・取得日時・ビルド日時を表示し、推測で補完しません。

JSONは任意の`geoip`ブロックと各事案の`geoip`を追加します。CSVは既存列を維持し、metadata / incidentの`details_json`に格納します。CLIは上位5群・5 IP、HTMLは保持した全群・IPを表示します。DB-IPの出典・ライセンスリンクもHTMLに記録します。

LRUはヒット・未収録結果ともIP単位で最大`--max-keys`件。リクエスト集計のIP保持も同じ上限で、超過時は部分解析と件数の下限を明示します。群ごとのIP・技法サンプルは64件までです。MMDBはメモリマップするため、キャッシュ以外にDBサイズに応じたアドレス空間・ページキャッシュを使用します。解析中はDBファイルを変更・切り詰めず、更新版は次回解析から使ってください。

調査・設計は[GeoIP設計](docs/geoip-design.md)、取得・更新と復旧は[DB管理](docs/geoip-database-management.md)、再現テストと性能は[GeoIP検証](docs/geoip-testing.md)、ライセンス全文は[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)を参照してください。

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

gzipの圧縮後サイズが小さくても、展開と各行の解析には時間がかかります。バッチ解析の `--max-file-bytes` は非圧縮入力にも適用されるファイルごとの読み取り上限で、既定の8 GiBは処理時間や入力全体の総量を制限しません。通常のログが展開後256 MiB以内なら、余裕を取った512 MiB（536870912 bytes）から設定を始め、想定する最大ログサイズに合わせて調整してください。

```sh
webaudit access.log.gz --max-file-bytes 536870912
```

上限を超えたファイルは途中で打ち切り、警告・部分解析状態・終了コード1を返します。残りの内容は解析されないため、その結果を全件解析として扱わず、ログを分割するか、必要な資源を確保して上限を上げて再実行してください。

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

## 提出用報告書一式（段階的実装）

既存の単一ファイル出力とは別に、新しいディレクトリを排他的に作成するバッチ出力を利用できます。11章構成の日本語・英語HTML、原本来歴・解析メタデータ・調査観点カバレッジ・全件証跡・全アクセス統計・事案別の追加調査案内を生成します。[設計と要求対応表](docs/reporting/design.md)を参照してください。

```sh
webaudit access.log --report-dir report --system-name "対象システム" --investigator "調査担当者" --report-title "アクセスログ調査"
```

`--investigation-background`、`--investigation-purpose` も任意指定できます。未指定値は空のまま保持します。`--lang ja|en` に対応します。`--report-dir` は `-o` / `--format` と併用できません。`--max-report-bytes` と `--max-spool-bytes` の既定値はそれぞれ1GiBです。

`report.json`、`report.html`、`manifest.json`、`log-inventory.csv`、`diagnostics/parse-errors.csv`、`diagnostics/excluded-requests.csv`、`diagnostics/execution-log.txt` を生成します。manifestは自身を除く成果物のSHA-256とバイト数を記録します。原本のSHA-256はgzip展開前のファイルbytesが対象で、前後のハッシュを照合します。原本hashの読込み上限にも `--max-file-bytes` を用い、完全なハッシュを取得できない場合や途中で変更された場合は不完全として明示します。

診断の別紙は `--max-keys` 件までの例です。空行を除外として記録し、同一ファイルの除外は明示的な `--dedup-files` 指定時だけ行います。欠損値はJSONのnull・CSVの空セルで示します。カスタム正規表現の本文はmanifestに保存しません。元ログのパス・証跡には機密情報が含まれ得るため、原本と同様に取り扱ってください。

出力失敗時は `INCOMPLETE` が残ります。そのディレクトリを完成した報告書として扱わないでください。既存ディレクトリは空でも再利用しません。

`analysis-rules.csv` はWebAudit署名・行動/統計分析・Hub・Aura署名/集計・GeoIP類似性の条件と対応状態を一覧化します。`analysis-coverage.csv` と `report.json.coverage` は評価状態と検出有無を別々に記録します。未対応、未実施、評価不能、部分評価、検出あり/なしを区別します。ルール無効化の設定は現行CLIに存在しないため、対応済みルールは有効、未実装ルールは未対応として記録します。

WebAudit署名では元観測ごとの一致ルール数を検出数、複数ルールに一致しても1件を検出リクエスト数として扱います。Hubの `matched_candidates` はbucket成立前のフィルター一致候補であり、アラート数や不審リクエスト数とは別です。独立エンジンの検出リクエストの全件関連付けはPhase 3で追加します。それまでは取得できない件数をnull/空欄とし、代表証跡から全件を推測しません。

全アクセス数と観点別件数は加算関係ではありません。同一観測が複数観点・複数ルール・複数エンジンに該当できます。観点の共有ルール（例: traversal/LFI）も独立した攻撃数ではありません。統計分析は必要な母数が不足すると評価不能になり、未対応のIPレピュテーションや本文攻撃は「検出なし」と表示しません。


### 不審リクエストと関連証跡

報告書一式には `suspicious-requests.csv`、`related-requests.csv`、`detections.csv`、`findings.csv` を含みます。元ファイルIDと行番号に基づくrequest ID、engine/ruleに基づくdetection ID、既存のfinding IDで追跡できます。同内容でも異なる行・原本は別観測であり、複数ルール・エンジンに一致してもsuspicious一覧内では1行です。事案全体の成否をリクエストに転記しません。

直接の署名一致・成立したHub検出の構成観測・単一応答のサイズ異常を不審リクエストとして出力します。WebAuditの時間窓/peer/hour分析とAuraの集計条件に属する観測は、正常アクセスを含み得る関連証跡として出力します。両方に該当する観測は両CSVに現れますが、direct_detection_ids / related_detection_ids で関係を区別できます。2つのCSVの行数を足して一意の不審リクエスト数としないでください。

解析中の観測はprivateなサイズ上限付きJSONLへ一時記録し、解析終了後に確定した検出と照合してCSVへストリーム出力します。元ログの再走査は行わず、終了時成立の統計も関連付けます。Hubのdistinct条件と抑制期間は実際のbucket所属トークンで追跡し、成立しなかった候補を検出に変えません。一時spoolは通常終了・出力失敗時に削除します。強制終了後のINCOMPLETEディレクトリは元ログと同等の機密性で扱ってください。

`report.json.evidence_complete` が全件出力の完全性を示します。spool上限・原本変更・解析上限等があればfalseとなり、理由と下限件数を記録します。圧縮原本のhash上限と展開後の解析上限は同じ `--max-file-bytes` の値をそれぞれ適用します。CSVには生ログ、URI、Referer等の機密情報が含まれ得ます。


### 全アクセス統計

`statistics/` にメソッド・ステータス/クラス・IP・ホスト・URIパス・User-Agent・国・ASN・ログ種別・プロトコルの各 `*-summary.csv`、`timeline.csv`、`numeric-summary.csv` を出力します。共通の `report.json.statistics` に同じ値を記録します。集計母集団は解析できた重複除外後の元観測であり、access/errorログに同一の実HTTP処理が重複記録されていても、ネットワーク上の同一要求だとは確認しません。

各表は `--max-keys` の種類数まで保持し、超過分はその他へ集約します。合計件数と割合の分母は全解析済み観測で、ユニークIP数が完全でない場合は下限値と明記します。値の表示長にも上限があります。国・ASNはDBが実際に利用可能な場合だけ集計し、悪性の根拠としません。Geoグループ内のユニークIP追跡は共有キー上限を持ちます。

時系列はUTCで、通常は分別、長い期間は時間別・日別へまとめます。小さいキー上限ではさらに粗い固定秒区分へ変更し、実際の粒度をCSVに記録します。ログのない時間帯を欠損・停止と断定しません。タイムゾーン不明な観測は別件数です。

レスポンスサイズは既知のゼロを含み、欠損を平均の分母へ入れません。処理時間はNginx JSONの `request_time`（秒）または明示的なカスタム正規表現の `duration_seconds` グループだけを使用します。未取得値・不正値・ゼロを区別し、巨大な数値で浮動小数点の合計が表現できない場合はsum/meanをnullにしてoverflowを明記します。原本は変更しません。


### 報告書の表示と証跡の扱い

`report.html` は外部通信なしで表示・印刷できます。11章の目次、観点別カバレッジ、事案一覧と独立したHub/Aura検出一覧から詳細へ移動でき、詳細から一覧へ戻れます。グラフには値とラベルを併記します。HTMLの表示は事案・独立検出各100件、ルール・カバレッジ各1000件などに制限し、全件データはCSV/JSON別紙で確認します。

代表的な生ログは詳細に、保持上限を超える不審リクエストは`suspicious-requests.csv`に出力します。`related-requests.csv`は集計条件に関連する正常アクセスも含み、全件を不審とみなしません。同じ入力ファイル・行の観測は複数エンジンに一致しても一意に数えます。別ファイル・別行の同文ログは別の観測です。実際のネットワーク取引の一意性は保証しません。

既定ではクエリの一般的な秘密キー、Authorization、Cookie等の機密値をマスクします。元ログは変更せず、ファイルID・行番号・生成リクエストIDを保持します。全ての個人情報を検出する機能ではありません。明示的に元の証跡値が必要な場合は`--include-sensitive-evidence`を指定できます。制御文字・双方向制御文字はこの指定にかかわらず可視エスケープします。報告書一式は元ログに準じたアクセス制御で保管してください。

重要度は既存ルールの優先度を継承し、影響の確定評価とは区別します。攻撃らしさのスコア、検出確度、成否、成否の証拠強度を分離し、校正された確率に変換しません。観測事実・推定・未確認事項を分け、HTTP 200/403/404のみで侵入や失敗を断定しません。追加調査と予防策の検討を区別し、該当事案の時間帯・IP・ホスト・URIと既存の攻撃別確認案内を出力します。


報告書一式の[利用方法・出力契約・件数定義・制約](docs/reporting/output.md)、[要求対応表とテスト](docs/reporting/traceability.md)、[性能と資源使用量](docs/reporting/performance.md)。[日本語サンプル](examples/investigation-ja/report.html) / [英語サンプル](examples/investigation-en/report.html)。

`--verbose` は stderr に入力ファイルのプログレスバーと読み取り行数を表示します。単一の大きなファイルでも行数は約100ms間隔で更新します。バーは列挙したファイルの処理済み数（重複除外・読み取り失敗を含む）で、解析やレポート生成全体の成功率ではありません。gzip、ディレクトリ、`--report-dir` にも対応します。完了時は改行し、通常レポートのファイル別診断は従来どおり表示します。stdout のレポート形式は変わりません。
