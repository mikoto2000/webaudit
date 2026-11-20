# GeoIPデータベース管理

```sh
webaudit geoip download
webaudit geoip update
webaudit geoip status
webaudit geoip rollback
```

`download`は初回用。正常な管理DBがあれば通信・再ダウンロードせず現状を表示する。`update`は未導入なら初回取得し、公式各ページのMMDBリンク/公開年月/展開後SHA1からCountryとASNの更新要否をそれぞれ判定する。更新不要でも最終確認日時を更新する。公開年月は時計から生成しない。`status`と`rollback`は完全オフライン。rollbackは現在のDBが破損していても、保持した前世代が検証可能ならペアで復元する。

保存先は絶対`XDG_DATA_HOME/webaudit/geoip`を優先する。空・相対XDGは無視。Windowsは絶対LOCALAPPDATA、Linux/macOSは絶対HOME/.local/shareをフォールバックとする。環境変数が使えない場合は分かりやすいエラー。管理者権限不要。

`metadata.json`に有効世代と前世代、各DBの提供元・種類・公開版・元URL・取得日時・MMDBビルド日時・サイズ・SHA256・配布元SHA1、最終確認日時を保持する。DB本体は`versions/gen-*/country.mmdb`と`asn.mmdb`の不変ファイル。版が異なるペアも各DBの実際の版を保持する。

writerはLinux/macOS flock、Windows LockFileExによる排他ロックを取る。競合は明確なエラーで再試行を案内し、プロセス終了時はOSがロックを解放する。`.lock`ファイル自体は残してよい。ダウンロードと検証は`.staging-*`内、両方成功後に世代を配置し、一つのmanifestを同じディレクトリ内で原子的に置換する。ファイルをSyncしてから公開する。WindowsはMoveFileEx(REPLACE_EXISTING|WRITE_THROUGH)を用いる。電源断に対する永続性の最終保証はファイルシステムに依存する。

失敗時は現manifestとDBを維持し、次のwriterが中断stage・manifest一時ファイル・孤立世代を回収する。現世代と前世代以外は削除を試みる。Windowsで古いreaderが保持中の世代は警告して削除を延期し、次の更新時に再試行する。使用中DBを上書きしない。解析中はDBファイルを手動で書き換えない。

通信は管理コマンドdownload/updateだけ。HTTPS・公式ホストとパスのallowlistを初回と各redirectに適用し、認証情報・任意port・queryを拒否する。proxyを使わずTLSを検証、HTTPクライアント45秒・コマンド全体5分、redirect最大5、ページ1MiB・圧縮64MiB・展開256MiBを上限とする。転送失敗・gzip CRC・配布元SHA1・MMDB Verify・全レコードの役割別schemaを検証する。SHA1は現行配布の転送確認であり、暗号学的な配布元署名ではない。ローカル整合性はSHA256・サイズ・種類・ビルド日時・公開版/URLの一致で検証する。

公式ページの構造変更時は推測でURLを生成せずエラーにする。HTTP 403等でも既存DBを維持する。実DBはGit・実行ファイル・テストへ同梱しない。公式配布とライセンスの根拠は[設計](geoip-design.md)、テスト計画と実測は[検証](geoip-testing.md)を参照。

## Phase B実機確認

2026-11-20、Windows amd64で新しい`geoip download`を専用のXDG作業ディレクトリに対して実行し、公式Country/ASNの2026-11版を正常に取得・schema検証・有効化した。Countryの実buildは2026-11-01T02:47:39Z、ASNは2026-11-01T02:52:43Z。通常の自動テストはこの通信や実DBに依存しない。
