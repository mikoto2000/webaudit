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

Phase Eで全テスト、100万行性能、管理DB/statusのネットワーク禁止実行、クロスプラットフォーム結果を追記する。
