# 提出用報告書の設計（Phase 0）

## 範囲と互換性

[要求仕様](requirements.md)のバッチ調査を対象にする。Go版のPhase 0–6を順にマージし、その後Java版へ同じモデル・成果物契約・境界テストを移植する。監視は対象外。既存のCLIとwebaudit/2のHTML/JSON/CSVは維持し、明示的な `--report-dir` で新しい報告書一式を生成する。既存ファイルを上書きしない。外部サービスと新しい依存は不要。

## 現行実装の調査結果

- `audit/input.go`: regular fileの探索、gzipの内容判別、行・展開後サイズ制限、パース不能診断、任意の同一原本除外。SHA-256は現在dedup時だけ内部利用。空行を無視し総行数・除外行数は未公開。
- `audit/signatures.go`, `normalize.go`: 宣言型L1ルール、最大7種類の検出用URL変形。アプリ側の解釈の断定はしない。
- `audit/analysis.go`: 2区分の5分窓、leaky bucket、同一ホスト・メソッド・パス・statusのサイズ履歴、peer MAD統計。全件証跡は未保持。windowとglobal統計の関連証跡を直接の攻撃と扱えない。
- `audit/incidents.go`: IP/host/UA/family/5分区分の事案。観測数は事案間で重複し得る。最大8代表証跡、成否は既定不明でHTTP 200だけで成功確認しない。攻撃スコアと成否確信度は独立。検出確度への変換根拠はないためunknownとする。
- `audit/upstream.go`, `aura_behavior.go`: Hub bucketとAura署名・集計は独立。alert countの合算を一意なリクエスト件数に使えない。元行参照とHTML用最大8生ログを保持。
- `audit/geo_analysis.go`: 既存国/ASN集計、DB来歴、5分/パス/host/カテゴリの類似性ヒント。悪性・主体同一性の証明ではない。
- `audit/report.go`, `report.html`: boundedな調査用出力と日英翻訳。提出用11章、manifest、全件別紙、全アクセス統計、調査観点coverageは未実装。
- Java版は同じ責務をLogInput/Signatures/Behavior/Correlator/Upstream/AuraAnalysis/Reportsへ分割。map-basedモデルであり、共通のJSON契約で比較できる。

## データと識別子

Requestは原本ファイル識別子＋元行番号で識別する。同内容の異なる行・ファイルは別観測。dedupは明示指定時のみ除外。Detectionはengine/rule/対象group/期間から安定IDを生成し、Findingは既存WA-IDを維持。RecommendationとCoverageは別モデル。確度・成否・scoreの意味は混ぜない。

新しい共通モデルはlegacy reportを参照し、metadata、inventory、coverage、detections、statistics、recommendations、completenessを追加する。Request全件をメモリ上に載せない。unknownはnull等でゼロと区別し、件数には exact/lower_bound/unavailable を持たせる。coverageは実施状態・完全性・hit有無を別属性にする。

## 全件証跡の方式比較と決定

| 方式 | 利点 | 制約 |
|---|---|---|
| 直接ストリーミング | 最小メモリ | 終了時成立の検出とfinding IDが未確定 |
| 元ログ再走査 | 中間ディスク不要 | ローテーション・変更・gzipの再処理。原本hash一致の確認が必須 |
| ディスクindex | 照会が高速 | DB依存と容量/整合性管理が増える |
| bounded JSONL spool＋終了後照合 | 解析時の観測を固定し遅延検出へ照合できる | ディスク上限と個人情報管理が必要 |

依存を増やさないbounded JSONL spool方式を採用する。解析中に元行・正規化・直接検出を記録し、終了後に保持された検出の対象条件へ照合してCSVへストリーム出力する。終了時の統計・windowは直接検出と関連証跡を区別し、関連付けだけではsuspiciousにしない。spoolには専用privateディレクトリ、排他的作成、サイズ上限を用い、終了時に削除する。打ち切り・保持されなかった検出・入力失敗は完全性に反映する。

原本のSHA-256は圧縮ファイルを含む保存状態の原本ファイルbytesを対象に前後照合する。hashを完全に取れない場合は値を捏造せずunavailable。解析中に変更された原本の全件出力を完全と扱わない。総作業量は入力読込み＋原本hash＋spool書込み/読込みでO(input)、メモリはO(maxKeys + maxFindings + maxEvidenceBytes)、ディスクは設定されたspool/output上限。上位表の打ち切りはその他・下限と明示。

## フェーズ契約と検証

| Phase | 成果 | 主な検証 |
|---|---|---|
| 0 | 本設計・要求対応表 | 現行コードと仕様の照合、自己レビュー |
| 1 | report-dir、原本inventory、hash、設定、manifest、診断 | gzip/空/不読/変更/排他的出力/既存CLI |
| 2 | 全観点のrule対応とcoverage | 未対応とno-hitの分離、欠損・上限とhitの共存 |
| 3 | bounded spool、Request/Detection/Finding別紙 | 重複行/複数engine/遅延検出/上限/削除 |
| 4 | 全アクセスと不審アクセスの基礎・時系列・Geo統計 | 分母、欠損と0、集計上限、粒度 |
| 5 | 11章HTML、別紙、総合評価、推奨、日英、offline graph | 共通値、XSS/CSV、navigation、印刷、未知情報 |
| 6 | 統合・性能・sample・仕様 | 必須テスト観点、CPU/heap/disk、オフライン |

各phaseで最新mainから専用worktreeを作り、Red/Green/整理の小コミット、チェック、自己レビュー、PR、CI、merge、main更新、worktree削除を行う。docsのPhase 0は実行可能コードを変更せず、Red/Green対象はない。以後の挙動変更で先に失敗するテストを記録する。

## 不明情報の扱い

対象システム・背景・目的・実施者は任意入力。未指定を明記する。ログに存在しないduration、request ID、内部実行結果、本文、認証結果は推測しない。元ログの時刻・host・UA・protocol等は取得した範囲を記載する。error logを入力した場合にOSログ全体を一律に対象外としない。IP reputationとbody-only攻撃等は未対応。検出ゼロは安全の証明ではない。

## 安全性・レビュー基準

html/template/FreeMarker autoescape、CSVセル数式抑止、JSON serializerを再利用。グラフも信頼できないラベルをescapeし、外部資源とscriptに依存しない。CLI/実行ログはterminal-safe。コマンドラインを丸ごと保存せず許可済み設定だけ列挙し、機密を含むregex等をmanifestに平文で残さない。証跡に元ログと同等の機密性があることを明記し、マスキングと原本追跡情報を分離する。
