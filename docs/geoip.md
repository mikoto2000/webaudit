# GeoIP / ASN

DB-IP Liteの初回取得は`webaudit geoip download`、更新は`webaudit geoip update`、オフラインの状態確認は`webaudit geoip status`です。取得済みDBは通常解析で自動利用します。明示DB指定と、管理DBが未導入の場合の従来の実行ファイル相対配置も維持しています。

- [調査・設計と公式配布の確認](geoip-design.md)
- [保存先・メタデータ・原子的更新・復旧](geoip-database-management.md)
- [テスト・性能・オフライン検証](geoip-testing.md)

公開IPのGeoIPは調査補助にのみ使い、検知スコア・成否・確信度へ入力しません。DB-IPの帰属表示とライセンスは[THIRD_PARTY_NOTICES](../THIRD_PARTY_NOTICES.md)を参照。旧版の合成テスト/マイクロベンチマークは`measurements/geoip/`に保持しています。
