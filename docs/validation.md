# 実装・検証状況

以下は0.1.0完了時の履歴です。0.2.0の変更・互換性は[上流互換性](upstream-compatibility.md)、現行テスト結果は`measurements/upstream`を参照してください。同一行の既定重複除外は廃止し、HTTPエラー/syslogと固定上流辞書を追加しています。

## 実装済み

Apache Common/Combined、Nginx Combined、vhost prefix、明示的JSONキー、名前付き正規表現でのカスタム形式。複数入力・ディレクトリ・gzip・ローテーション、ストリーミング、読み込みエラー隔離、巨大行/UTF-8/CRC/展開量上限、重複検出、元ログ参照。L1 28ルール、L2 9検知、L3 5検知、相関と保守的な成否推定、HTML/JSON/CSVとCLI要約、ログ品質と保持上限の警告。ルールとHTMLは埋め込みで、ネットワークや外部サービスは使いません。

## 未実装・制約

任意のLogFormat自動推測、本文/WAF/アプリ監査ログ、実クライアントIPの信頼プロキシ解決、任意Unicode正規化、%u表現、厳密な全時点のrolling window、任意乱順の外部ソート、ディスクへの検知状態退避、全Hubルール/データ集合、裏付け証拠なしの成功/失敗確定。実ログ精度試験、GB級gzip性能、Windows/Linux amd64以外の配布検証、公開Releaseと署名も未実施です。

## テスト

- `go test -count=1 -json ./...`: 87件成功（subtest/fuzz seedを含む。top level 30件）、失敗0。開発補助コマンドのmetrics/benchmarkは別途実行して評価しました。
- `go vet ./...`: 成功。
- `go test -cover ./audit ./cmd/webaudit`: audit 90.0%、CLI 70.3%。ツールの行カバレッジは測定対象外です。
- `go test ./audit -run=^$ -fuzz=^FuzzParse$ -fuzztime=10s -parallel=4`: 成功。詳細は measurements/fuzz.txt。TDDのRED/GREENと境界値・欠損・誤検知の回帰はGit履歴とテーブル駆動テストに記録。
- HTMLのログ由来文字列エスケープ、外部スクリプト不使用、CSV数式対策、出力上書き拒否、シンボリックリンク入力の静的除外、gzip破損/上限、巨大行復帰、URL復号深度、重複JSONキー、欠損値の統計混入防止、証拠保持上限を確認。
- Goの一時coverageメタデータをOSのsandbox tempへ保存した最初の試行はrename権限で失敗。GOTMPDIRを作業領域内に指定して再実行し、上記の成功を確認。Go race detectorはCGOなしの今回のローカル構成では実行していません。

## 検知評価・性能

精度: TP42 / FP1 / FN1 / TN27、Precision/Recall/F1各97.67%、ケース単位FPR3.57%。合成ケースのみ。成否不明95.35%。[精度レポート](accuracy.md)に暫定判定の評価を別記。

100万行と3.11GB入力の実測、メモリ指標・条件・制約は[性能レポート](performance.md)に記録。

## 出典

AuraDFIR 32項目を調査、31項目の条件を独立実装へ対応付け、1項目を対象外。Hub 63シナリオを調査、30シナリオを対応付け、33を対象外/保留。これは条件レベルの対応であり、上流の全表現・外部データ・閾値との互換数ではありません。独自追加IDは6（WB-rate, WB-burst, WB-multi, WS-errors, WS-url-size, WS-size）。共通コンセプトを持つ出典との重複やcount/byteを統合した検知があるため、対応元数と出力ルール数は一致しません。

## Gitと工程

親ディレクトリは初期化せず、webaudit/.gitを開発対象のGit境界にしました。参照リポジトリは読み取りのみ。各Phaseを専用worktreeで進め、元のRED/GREEN履歴を保持しています。

当初、sandbox内のDNS制限をGitHub CLI認証不良と判定し、Phase 0〜5をローカルmainに先行マージしました。ネットワーク境界外で認証を再確認後、同じコミットをworktreeで再検証し、PR #1〜#6として順にレビュー・マージしました。Phase 6はPR #7。最終実装head 89779435714cd97ffa5cb028e5305683d1f0b9cd のWindows/Linux CIが成功しました（[実行結果](https://github.com/mikoto2000/webaudit/actions/runs/44688028947)）。この後のレポート参照先修正と記録更新もPRで再確認してからマージします。初期PhaseにはリモートCIが存在せず、成功したローカル検証と空のstatusを確認しています。最終PhaseにはWindows/LinuxのCIを追加し、Linux上でもテスト・CLIのサンプル解析・fuzzを実行しました。最終PR・main SHA・CI・後片付けの実結果は完了報告で示します。認証情報は成果物に保存していません。

## 成果物

Windows/Linux amd64の単体バイナリとSHA256SUMSはdist/（Git追跡外）、ハッシュは measurements/binaries.json。README、ルール台帳、競合調査、出典、設計、精度・性能レポート、examples/の合成ログとHTML/JSON/CSVサンプルを含みます。

本体バイナリの依存パッケージも確認し、ネットワーク関連はアドレス/URLの純粋な解析を行うnet/netipとnet/urlだけでした。net/httpやnetの接続API、os/execは本体依存にありません。パケットキャプチャによる検証は行っていません。CLI OAuth credentialのworkflow scope不足は、接続済みGitHub appで同じcommitのbranchを作成する方法で解決しました。

配布ビルドは `-trimpath -buildvcs=false` とCGO_ENABLED=0を指定し、作業パスや未コミット時のVCS情報を埋め込まない構成です。コミットの同定は最終mainとPR履歴、配布物の同定はSHA256SUMSとbinaries.jsonで行います。ライセンス表示と文書を同梱したzip/tar.gzもdist/に作成しています。

## 配布物の改行と再現性

マージ後の再ビルドで、Windows上の作業ファイルに混在したCRLFと、Git内のLFとの差が埋め込みHTML/JSONのバイト列を変え、配布ハッシュが変わることを検出しました。解析動作の回帰テストは成功していましたが、ビルド再現性のため追加修正を行いました。

`.gitattributes`で埋め込み資産を含むテキストのLFを指定し、クリーンなcheckoutを起点に配布物を再生成しました。Go 1.27.4、CGO_ENABLED=0、-trimpath -buildvcs=falseで、mainと別worktreeから作るWindows/Linux両バイナリがそれぞれ同じSHA256になることを確認しています。生成スクリプトが改行変換する可能性があるため、配布ビルドはクリーンなcheckoutから行ってください。最新の実行ファイルハッシュはmeasurements/binaries.jsonです。
