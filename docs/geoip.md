# GeoIP / ASN: Phase 0 / 4 / 5 / 6

## Phase 0 — 提供元・ライセンス・ライブラリ

2026-11-20に公式情報を調査。

- [DB-IP Lite公式](https://db-ip.com/db/lite.php): Country / ASNをMMDBで提供。月次更新、商用版より低い精度・収録率。CC BY 4.0で出典表示が必要。HTMLにリンク付きの「IP Geolocation by DB-IP」を表示する。DBはユーザーが別途準備し、製品には同梱・自動ダウンロードしない。
- [maxminddb-golang v2.9.1](https://github.com/oschwald/maxminddb-golang/tree/v2.9.1): ISC。netip.AddrによるIPv4/IPv6検索、メモリマップ、Reader.Verifyで全体構造を検証できる。より高水準のGeoIP2 APIを介さずDB-IP互換フィールドを直接読む。固定したソース・依存ライセンスをvendorに保存し、通常のビルド・テストではネットワークを必要としない。
- [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)、[IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml): private、loopback、link-local、shared、multicast等を分類。文書用・benchmark・protocol assignment・変換用範囲・未割当IPv6は保守的に検索しない。国コードは居住地・国籍を意味しない。ASNは個人や組織の攻撃関与を示さない。

## Phase 4 — 情報付加・キャッシュ・相関

`OpenGeoIP`で解析前にローカルDBを開いてVerifyし、`Close`で解放する。CLI指定を役割ごとに優先し、実行ファイル相対のgeoipディレクトリで固定名、月次名の順に検出する。不存在の自動DBは無効、破損した自動DBは警告、明示指定のエラーは終了コード2。

公開IPだけを検索する。Countryのiso_code / names.en、autonomous_system_number / autonomous_system_organizationを読む。欠損・未収録・未設定はnull。DB種類とbuild_epochから提供元・UTC更新日を記録する。プロバイダーが判別できないDBの提供元・ライセンスはunknown。ファイルのmtimeから更新日を推測しない。

ヒット・ミスのLRUは最大max-keys件。IPv4 mapped IPv6はIPv4と同じキー。集計用peer表もmax-keys件に制限し、超過後は既存peerの件数を継続して新規peerを保持せず、partialと下限件数を明示する。群数は保持peer数＋既存事案数で有限、群のIPと技法サンプルは64件まで。複数IPの調査フラグ判定は2件で十分なので各ASNの集合を2 IPで打ち切る。

全検出と成否判定の完了後に事案へ付加し、国別・ASN別に既存事案を数える。ASN内の複数不審IPと技法、通常アクセスも含むリクエスト集中を表示する。新規ルール・危険度加算・事案統合には使用しない。上流アラートをWebAudit事案数へ混ぜない。未知ASN同士を同一組織として扱わない。

## Phase 5 — レポート

GeoIP未設定は既存のJSON/CSV/CLI/HTML形式を維持する。有効時だけ任意geoipフィールドを追加し、事案・peer・国別・ASN別集計、DBパス・役割・種類・更新日・提供元を出力する。CSVは既存列のdetails_jsonを使用する。HTMLのDB由来文字列もテンプレートでエスケープし、出典リンクと依存ライセンスを記録する。CLIは各表上位5件で、完全な保持範囲はJSON/CSV/HTMLを使う。

## Phase 6 — 検証

TDDのREDコミットで公開API・IPv4/IPv6・分類・未収録・DB未指定/破損・キャッシュ・集計・危険度不変・出力のテストを先に失敗させ、実装後にGREENを確認した。自動検出優先順位、片方のDBのみ、構造破損、上限と通常アクセス、HTMLエスケープ、CLIエラーも回帰テストに含む。

`audit/testdata/geoip/generate.py`はPython標準ライブラリだけで小規模MMDBを生成する。8.8.8.0/24と2606:4700::/32に架空の国・組織を割り当てた合成データで、現実のGeoIP正確性を評価するデータではない。外部のDBやサービス、ダウンロードは不要。

Linux CIの`python3 tools/verify-offline.py`はseccompでsocket/connect等を呼ぶと即終了する子プロセスを使う。制限が機能することを接続試行で自己検証した上で、GeoIPなし・明示指定・実行ファイル相対自動検出、IPv4/IPv6/非公開/未収録/反復IPをCLIで解析する。JSON/CSV/HTMLすべての出力経路を実行する。GoテストとvetもGOPROXY=off/GOSUMDB=offで実行する。

ローカルの単発マイクロベンチマーク（Windows amd64 / Core i9-12900 / Go 1.27.4）ではキャッシュヒット204.4ns/op、0B/op、異なるIPは749.1ns/op、177B/op。後者は主に合成DBの未収録検索であり、実DB全体の速度を保証しない。大量IP後もLRUとpeer数が上限以内であることは機能テストで検証する。MMDBのマッピングや他の解析表もあるためプロセス全体のメモリ上限ではない。

検証記録: [テスト概要](measurements/geoip/summary.json)、[全テスト](measurements/geoip/tests.jsonl)、[性能](measurements/geoip/benchmarks.txt)。CIのオフライン動作結果はPRのChecksを参照。
