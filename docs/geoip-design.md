# GeoIP / ASN自動管理 — Phase A

## 調査と差分

開始: main `65c55f3f1af5737ef086d25e0be4f00c279f6ed1`、作業ツリーclean。
既存のaudit/geoip.go、geo_analysis.go、CLIと各レポート、合成MMDB・テストは維持する。
不足はDB取得・更新・状態表示、ユーザーデータ保存先、永続メタデータ、検索状態、IP数と類似性、100万行性能検証。既存の国/ASNによらない検知・成否推定を変えない。

2026-11-20、[公式Liteページ](https://db-ip.com/db/lite.php)、[Country配布](https://db-ip.com/db/download/ip-to-country-lite)、[ASN配布](https://db-ip.com/db/download/ip-to-asn-lite)、[Country MMDB仕様](https://db-ip.com/db/format/ip-to-country-lite/mmdb.html)と実際の両配布ファイルを確認した。登録・APIキーなしのHTTPS公開リンク、gzip圧縮、月次更新。CC BY 4.0とリンク付きDB-IP attributionを継続する。

公式各ページのMMDBダウンロードリンクから版とURLを読む。現在時刻から年月を生成しない。URLは`https://download.db-ip.com/free/dbip-{country,asn}-lite-YYYY-MM.mmdb.gz`。ページ変更・複数候補・欠落はエラーとする。公式表示のMD5/SHA1は**展開後MMDB**の値であることを実ファイルで確認した。SHA1は改変耐性の保証には使わずHTTPSの転送確認に用い、永続整合性には自前で計算したSHA-256を使う。

実測（実DBは非追跡作業領域だけに保存）:

| DB / 公開版 | gzip bytes | MMDB bytes | MMDB SHA1 | MMDB SHA256 |
|---|---:|---:|---|---|
| Country / 2026-11 | 4205904 | 8515063 | 09eea8433fe3eed71984fd6aac9d8ab3d9ca51f0 | 145ce5dfb812d8de28547e6289bb5c5f8b3df2f1dea21d324d5b575e0431311f |
| ASN / 2026-11 | 5237630 | 9648279 | b8f3693d20560dcd0ccee556833ad2d362dec951 | 81565a450281c949fc83745f5ec9cfea70b035163b1152b055645884765d153d |

## 保存・安全な公開

有効な絶対XDG_DATA_HOMEを優先し、LinuxはHOME/.local/share、WindowsはLOCALAPPDATAを使う。空/相対XDGは無視、フォールバックもなければ管理コマンドは明確なエラー。解析は警告して継続する。

`internal/geoipdb`にパス・メタデータ・ローカル検証、公式提供元と更新を置く。ネットワーク機能はdownload/updateからだけ呼ぶ。公開先はユーザーデータ内`webaudit/geoip`。明示DB > 管理DB > 従来の実行ファイル相対geoip（管理DBが未導入の場合のみ）の順とし、既存の配置方法も保つ。壊れた管理DBから黙って古いDBへ切り替えない。

更新はOSのファイルロックで単一writerにし、両DBを不変の世代ディレクトリで完成・検証した後、一つのmetadata.jsonを原子的に差し替える。旧世代のMMDBを上書き・リネームしない。解析は一回読み取った世代を使い続ける。失敗は現世代・メタデータを維持し、中断後のstageと孤立世代は次のwriterが回収する。前世代を一つ保持し、検証済み前世代へ戻せるrollbackも用意する。Windowsの使用中旧世代は削除失敗を許容し、次回の再試行対象とする。

## セキュリティと検証計画

HTTPS・許可ホスト・許可パスを初回URL/リダイレクトとも検査。タイムアウト、ページ/転送/展開の上限、gzip CRC、SHA1、MMDB Verify・役割/全レコード型の検査を行う。メタデータのパス逸脱・SHA256不一致も拒否する。API・DNS検索・通常解析中の自動更新は追加しない。

各Phaseに専用worktree/PRを用い、Red → Green → Refactorを細粒度コミットで記録する。Bは注入したHTTPクライアント・時計・失敗点と合成MMDBで全更新境界を検証、Cは管理DB検出/検索状態と互換性、DはIP数/類似性/出力、Eは両OS CI・seccompオフライン・100万行の実測を行う。外部サイトに依存するテストは作らない。
