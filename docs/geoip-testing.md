# GeoIPテスト・検証

## 再現方法

```sh
go test ./...
go vet ./...
python audit/testdata/geoip/generate.py
go run ./tools/geoip-example
# Linux amd64のみ
python3 tools/verify-offline.py
```

通常テストは公式サイトや実DBに依存しない。標準ライブラリで再生成できる合成MMDB、fake Source、注入したHTTP RoundTripperと時計を使用する。IPアドレスが実在しても合成DBの国/ASNは架空。DB自体の第三者データは含まない。

Phase Bはパスの空/相対/Unicode/スペース/OSフォールバック、配布ページ変更、HTTP 404/500、timeout、redirect allowlist、転送上限/途中切断、gzip/展開上限、MMDB破損/役割違い、既存導入、更新不要/片方/両方、失敗時manifest不変、整合性とrollback、同時writer、OSロックのプロセス終了時解放、中断stage回収を検証する。更新失敗後に再試行でき、正常な旧世代を保持することを確認する。

Phase Cは管理DBの自動検出、明示指定優先、snapshotの維持、管理DB破損時の警告と通常解析継続、役割間違い、検索状態を検証する。既存IPv4/IPv6・特殊用途IP・キャッシュ・検知/成否不変のテストも維持する。

Phase Dは64表示サンプルを超える異なるIP数、既知ASN内のpath/category/時間区間を要求する類似性、不明ASNを同一ネットワークとしないこと、各形式の版/取得日時/検索状態、HTML escapingと既存形式を検証する。[合成HTML例](../examples/geoip-sample-report.html)は実DB不要で再生成可能。

## TDD記録

各Phaseは専用PR/worktree。追加振る舞いのRED、最小実装のGREENをコミットメッセージに記録し、成功状態だけをmainにマージする。Phase Aは設計のみ。既存テストで既に満たされる境界値の補足テストはその旨を履歴に残す。

## Phase E — 最終ローカル検証

Windows amd64 / Go 1.27.4で`go test ./... -count=1`は235件成功（サブテスト含む、top level 89）、失敗0。既存のHTTP製品固有ケース11件は従来の対象外としてskip。`go vet ./...`成功、Parse fuzzは5秒指定で98,352実行・クラッシュなし。合成評価は従来と完全一致（TP42 / FP1 / TN27 / FN1）。クロスビルドはWindows/Linux/macOSそれぞれamd64/arm64の6対象で成功。実行時検証はWindowsローカルとWindows/Linux CIを対象とし、macOS/ARM64のネイティブ実行は確認していない。

追加の回帰境界はgzip CRC、managed symlink拒否、IP分類単独、大量IP後のキャッシュ/peer上限、新世代が旧世代の検索キャッシュを再利用しないこと。元の世代を開いたreaderは以前の結果を保持し、新しいreaderは新世代の値を得る。

Linux amd64 CIの`tools/verify-offline.py`はseccompでsocket/connect等を試みるとプロセスを終了させる。制限自身の自己検証後、未導入/明示/従来配置/管理DBの通常解析、JSON/CSV/HTML、未導入/導入済みstatus、導入済みdownloadの無通信、破損statusとGeoIP無効化を実行する。テスト用の管理manifestも合成MMDBから構成し、外部サービス不要。source providerのHTTP境界は注入Transportで検証する。

## 100万行測定

測定環境: Windows amd64、12th Gen Intel Core i9-12900、24論理CPU、Go 1.27.4。各行は正常な`GET /api/items`、200、Mozilla UA。各ケースを100万行で逐次・単発実行。Country/ASNは事前取得した実DB-IP 2026-11版（ファイルSHA256と実build/取得情報を生データへ記録）。明示ローカルMMDBのReader.Verifyと解析処理を測り、ネットワークは利用しない。XDG manifestの全レコード整合性検査はこの性能表の対象外。

| 入力（各100万行） | GeoIP | 読取開始〜解析完了 秒 | 最大process working set MiB | 最大sampled Go heap MiB | MMDB実検索 | cache hit |
|---|---|---:|---:|---:|---:|---:|

| 2 IP反復、IPv4/IPv6半数ずつ | なし | 98.859 | 60.00 | 6.66 | 0 | 0.00000% |
| 2 IP反復、IPv4/IPv6半数ずつ | あり | 94.985 | 43.42 | 10.45 | 4 | 99.99980% |
| 100万の異なるIP、IPv4/IPv6半数ずつ | なし | 90.247 | 60.26 | 35.70 | 0 | 0.00000% |
| 100万の異なるIP、IPv4/IPv6半数ずつ | あり | 90.134 | 83.94 | 39.44 | 8192 | 0.00000% |

反復ケースの差は-3.92%、異なるIPケースは-0.13%。OSキャッシュ・GC・ホスト負荷等の差を含む単発値で、高速化を示す根拠にはしない。Windowsのprocess peak working setはGetProcessMemoryInfo、Go heapは10msサンプリング。厳密なGo heap最大や将来のプロセスメモリ上限を意味しない。Reader openはGeoIPありで反復0.102秒、異なるIPは生データ参照。

反復では2 IPを保持し、peer cache 999,998ヒット＋事案への付加でLRU 44ヒット、MMDBはCountry/ASN合計4回。異なるIPは既定max-keys=4096のpeer保持で検索8,192回、残り995,904リクエストのGeoIP集計は未追跡として明示する。後者は解析のpartialと件数の下限を報告し、全100万IPのGeoIP情報を収録したとは扱わない。元の挙動/統計表の上限も同条件で適用される。両ケースともログ100万行を構文解析し、未解析0、GeoIP有無で検出結果（ID/IP/score/重要度/成否/確信度/技法/件数等）のhashが一致した。

キャッシュ選択は初期の0 allocationヒット測定と今回の反復/大量IP測定を根拠に、既存のbounded peer表＋negative cacheを含むbounded LRUを継続する。IP数が増えてもcacheは4096件で止まり、MMDB/ほかの解析表は別途メモリを使う。

再測定（合成MMDBなら外部DB不要、実測値と同じ実DBを使う場合は`-country PATH -asn PATH`を付加）:

```sh
go run ./tools/geoip-benchmark -lines 1000000 -scenario repeated_mixed
go run ./tools/geoip-benchmark -lines 1000000 -scenario repeated_mixed -geoip
go run ./tools/geoip-benchmark -lines 1000000 -scenario distinct_mixed
go run ./tools/geoip-benchmark -lines 1000000 -scenario distinct_mixed -geoip
```

生データ: [性能とDBメタデータ](measurements/geoip-managed/performance.json)、[テスト概要](measurements/geoip-managed/test-summary.json)、[全テスト](measurements/geoip-managed/tests.jsonl)、[合成精度評価](measurements/geoip-managed/accuracy.json)、[fuzz](measurements/geoip-managed/fuzz.txt)。CIとマージ履歴は各PhaseのPRを参照。

## 制限と復旧上の判断

通常解析・statusの開始時にwriterと競合した場合、解析は警告して自動GeoIPを無効にする。既に開いているreaderの解析は旧snapshotで継続する。更新中のDBペア混在を避けるための判断で、後から通常解析を再実行すれば公開済み世代を利用できる。statusはwriter終了後の再実行を案内するエラーを返す。

Windowsで保持中の古い世代を削除できない場合は回収を次のwriterへ延期する。更新中断は一つのmanifest置換とOSロックで保護するが、ストレージの電源断・媒体故障に対する耐久性はファイルシステムに依存する。公式ページ変更や配布障害時は推測URLで続行せず、正常な現世代を維持する。既知の検知上のFP/FNは今回変更しない。

Windowsの保存先にはdrive絶対パスに加え、末尾区切りのないUNC share root（backslash/forward slash表記）も受理する。追加RED/GREENテストで境界を確認した。
