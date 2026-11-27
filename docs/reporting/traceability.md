# 要求と実装の対応表

要求の原文は[requirements.md](requirements.md)。表の章番号は原要求に対応します。現在の表示は旧第4章を付録Aへ移し、旧第7章の重複する一覧表と旧第9章の総合評価を削除して、旧第10章の制約を第2章・事案詳細・付録Cへ分け、調査方法と全体統計を付録D・Eへ移して、本文を第1〜5章とし、追加調査の依頼と結果報告を第6章として統合しています。必要な結論・注意は第1章と事案詳細へ移しています。一覧は現在の第3章、詳細は第4章、全保持対象はCSVで確認できます。各章の列挙項目は該当する行の範囲に含む。完了時には根拠となるモデル・テスト・成果物を更新し、未対応を完了と表現しない。

| 要求 | Go版の最終実装/検証 | 制約・未評価事項 |
|---|---|---|
| §1–2 offline/再現性/batch/互換性 | bundleは明示モード、既存検出再利用。全既存テスト、Linux seccomp付きoffline CI | 外部LLM/API不使用。任意DB/OS監査を自動理解しない |
| §3 第1章 概要 | 共通summary/metadata、入力・request・検出・事案・優先度別。presentation/integration tests | 入力任意metadataは未指定表示、下限と評価不能を区別 |
| 第2章 対象 | LogInventory、保存状態SHA-256、format/field/timezone/診断。bundle_test | 前後hash照合で観測できない瞬間的変更は保証外 |
| 第3章 方法 | 実効settings、全rule metadata/条件/必要field、limits、parser/normalization/windowの説明 | 既存source互換範囲・順序依存を明示 |
| 旧第4章 評価軸（現在は末尾の付録A） | severity、検出confidence、outcome、outcome evidence strengthを独立表示。TestOutcome | 検出confidenceは独立した校正根拠未整備でunknown。severityは既存優先度の意味 |
| 第5章 統計/グラフ | 全観測次元・数値・adaptive UTC timeline/Geo、offline meter。statistics/presentation tests | Geoなしは未実施、durationは明示単位のみ。上位/other/下限を開示 |
| 第6章 coverage | 全41観点＋全既存rule。状態/完全性/hit独立、direct/related union counts。coverage/integration tests | 本文専用・reputationは未対応、Geo request membershipはnull、共有rule観点は部分支援 |
| 第7章 一覧 | native事案と独立source検出を別表、優先度順、詳細リンク/戻りリンク。presentation tests | engine間の自動事案統合なし、同観測の一致は全件CSVのIDで追跡 |
| 第8章 詳細 | 既存証拠/正規化/条件/成否/調査案内＋共通case統計・事実/推定/未知/条件付影響 | 原本request IDではなく生成ID。代表ログ上限8と全件CSVを区別 |
| 第9章 総合評価 | 共通集計、集中の統計への参照、possible-successと優先事案への参照 | 共通主体・侵入・被害を断定しない |
| 第10章 制約 | 冒頭部分解析、一般制約と今回のwarnings/実効上限、入力別status | 実運用での精度検証/任意難読化の完全検出は保証外 |
| 第11章 推奨 | 既存攻撃別案内再利用。時刻/IP/host/URI、証拠、優先度、追加調査/予防策の別 | source独立検出の成否・優先度未評価は明示、任意システム構成を捏造しない |
| §4 全件 | bounded spoolで全観測固定、遅延検出との照合、直接/関連別紙。requests/integration tests | spool/事案/キー/証跡上限は部分解析、全件性を保証しない |
| §5 共通model | InvestigationReport、RequestSnapshot、BundleDetection、FindingObservation、CoverageRow、Recommendation | 公開JSONとHTML/CSVは同じ値。native singlefile schemaを維持 |
| §6 成果物 | output.mdの全成果物、排他的新規ディレクトリ、manifest全hash。bundle_test | manifest自身は自己hash除外、失敗出力はINCOMPLETE |
| §7 日英/UI | 本文6章（静的な旧入口は5章と第6章へのリンク）と末尾の付録A（旧第4章）・付録B（評価状況）・付録C（共通制約と共有）・付録D（方法）・付録E（全体統計）、全anchor検査、printCSS、外部資源なし、表示量制限、ja/en sample | ブラウザーがfile URLを禁止したため画面目視は未実施。静的検査は成功 |
| §8 安全性 | HTML/CSV/JSON注入防止、controls/Bidi可視化、secret masking、排他/temp/limits。presentation/integration tests | パターン外の秘密・個人情報の完全匿名化は非対応、共有前確認が必要 |
| §9 正確性 | 元file/line別一意request、各engine重複、0/null/quality、共通分母、部分解析。output.md参照 | 観測≠検証済みネットワーク取引。観点/engineの単純加算禁止 |
| §10–11 開発工程 | Phase0–6各専用worktree、RED/GREEN、PR/CI/merge/cleanup。下記PR表・作業記録 | Java移植はGo完了後に開始 |
| §12 必須テスト | 次表参照。既存＋bundle一式テスト/静的解析/CI | 実ログに対する攻撃分類精度は未測定 |
| §13–14 成果と測定 | output.md、performance.md、生値、ja/en sample、本表 | Java版は別repoで順次実装。Go単体完了を全体完了と呼ばない |


## Phase 1 実装記録

- `audit/bundle.go`: 明示的bundle API、private/exclusiveディレクトリ、原本hash前後確認、実効設定・build/rules hash・成果物hash、上限付き診断と未完了marker。
- `audit/input.go`: 任意bundle captureにより総行/空行/parse error/時刻・項目・ログ種別を既存streamから取得。legacyの構造・挙動は維持。
- `cmd/webaudit/main.go`: `--report-dir`、任意metadata、spool/output上限。既存-o/formatと排他。
- Phase 1のreport.htmlは既存調査画面を再利用する暫定出力。11章構成・全件・coverage・全統計はまだ未完了であり後続phase対象。
- 原本hashのbefore/after比較は、並行変更を完全にロックするものではない。変更が観測された場合は完全性を下げる。

Phase 1セルフレビューで、入力hash/診断の完全性低下を暫定HTMLの部分解析表示にも反映するよう修正。出力先はrenameで既存空ディレクトリを置き換え得る方式を避け、mkdirによる排他予約＋未完了marker方式を採用。


## Phase 2 実装記録

`audit/bundle_coverage.go` の共通ルール一覧・41調査観点・全ソースルールをJSONとCSVへ出力する。`incidents.go` と `upstream.go` の任意observerで既存検出結果を利用し、新しい検出器を追加しない。coverageはstatus/evaluation/complete/has_detectionsを独立させる。必要項目の欠損・入力部分解析・統計母数不足・未対応・GeoIP未実施を区別する。共有・部分支援の観点はlimitationsを明示する。

完全な不審/関連リクエストの関連付けとその件数はPhase 3で完成させる。現段階で復元できない独立エンジンの件数はnull/空欄としている。検出確度の既存数値からの変換はしない。既存coverage回帰テストを保持し、別ファイルにbundle契約テストを追加した。


## Phase 3 実装記録

- `bundle_requests.go`: サイズ上限付きprivate JSONL spool、全件CSVへのストリーム変換、Request/Detection/Findingの安定ID、独立engineのexact membership、aggregateのrelated証跡、出力完全性と理由。
- `incidents.go`: 従来の事案キーを共通関数に抽出し、実際に保持された事案へ関連付ける。8件の代表証跡上限は維持。
- Hubはdistinct適用後のbucket所属と実際にemitされたtokenだけを解決。Aura署名は実際のgroup一致を利用。遅延集計は元データを再走査せずspool snapshotへ照合。
- coverageのdirect検出リクエストとrelatedリクエストを別の列にする。独立したengineの件数を一意requestへ単純合算しない。
- findingsのURI例は最大8件/各1024bytes、methodキーは最大64種類/各128bytes。全件URIと元ログはメモリに保持しない。
- source/aggregate検出のinterval indexを構築し、各requestで無関係な全検出を走査しない。メモリは保持検出数に、spoolは明示上限に制限。
- 途中の検出元fieldがcompactされた場合は完全な照合を保証せず明示する。SIGKILL等の異常停止はINCOMPLETE markerで識別する。


## Phase 4 実装記録

`bundle_statistics.go` は解析中の全観測で全アクセス統計を計数し、spool replayの一意なdirectフラグで不審アクセスを計数する。spool上限に達しても全アクセス総数は失わず、不審件数の品質だけ別に記録する。各次元はmaxKeys・表示長で制限し、その他bucketの件数と下限ユニークIPを明示する。Geo情報は既存Lookupを再利用し、DB未利用をゼロ件の地理結果にしない。

時間粒度はadaptiveに統合し、負のUnix時刻を含めUTC区分とする。空白の期間をログ欠損とは扱わない。処理時間は単位が定義されたJSON/request_timeまたはcustom duration_secondsのみ採用する。欠損・0・不正値・数値overflowを区別する。parserが実際に通ったfamilyを非公開Event属性としてinventoryへ記録し、legacy JSONには追加しない。custom regexは本文を保存せずSHA-256を記録する。

テストは全アクセス/不審の分母、ゼロ/欠損、spool切詰時の全体件数、cardinality上限、期間に応じた時間粒度、Geo、NaNと数値overflow、parser familyを検証する。11章表示とグラフは次Phase 5で実装する。

Phase 4セルフレビューではGeoその他bucketに個別の国名/組織名を流用しないこと、欠損数値のsum quality、極端な年月での時系列ラベル、明示入力数の上限、custom regexの秘密を含むコンパイルエラーをbundleへ保存しないことも確認した。


## Phase 5 実装記録

`bundle_presentation.go`の共通summary/assessment/recommendationから11章HTML・JSON・CSVを生成する。既存の成否判定・攻撃別調査案内を再利用し、事実・推定・未確認・条件付き影響・追加調査と予防策を分離する。HTMLの集計はモデルの値のみを表示する。独立エンジンは別集計で、一覧/詳細/ルール/カバレッジのリンクと戻りリンクを備える。外部資源なしのラベル付きmeterグラフと印刷CSSを使用する。

事案・独立検出にunion request数、direct/related別、検出数、観測期間/平均頻度、status/method、URI別件数と上限付きユニークURI数、サイズ統計、時系列を追加する。時刻不明は捏造せず、入力ごとに観測timezone offsetも開示する。sourceのエラー/auth profileでは既存検出器に合わせてwall-timeと必要fieldだけを前提にする。

マスクは検出後の共通モデル/CSVスカラー/構造化JSONに適用する。代表証跡の参照はマスク前のfileID+lineから作成し、マスク後のパス衝突でも失わない。制御文字とBidi制御は可視化、HTMLは標準template escape、CSVは既存formula guardを再利用する。opt-outは明示flagのみ。ja/en章・静的文言・全anchor・CSV共通値・元ログ不変・全artifact機密値・制御文字の回帰テストを追加。


## Phase 6 統合テストの対応

| 必須観点 | 主な根拠 |
|---|---|
| 正常のみ/空/不審のみ/混在 | TestBundleNoHitEmptyAndFormulaSafeMetadata、FullRequestExport、StatisticsUseAllRequests |
| 複数rule/engine・同文別観測 | TestFullRequestExportPreservesDistinctObservationsAndSeparatesRelated、CoverageAspectCounts |
| 複数file/rotation/gzip/逆順 | TestBundleRotatedGzipOutOfOrderAndSharedCounts、BundleInventoryAndManifest、既存input tests |
| parse不能/必要field欠損/不読 | BundleInventoryAndManifest、DedupEmptyUnreadableAndPrivateSettings、CoverageNoHitAndInsufficientStatisticalBaseline、SourceAuthProfile |
| Geo有/無/DB不正 | BundleStatisticsGeoAndInvalidDuration、既存geoip/reporting/managed tests |
| 上限/入力変更/遅延検出 | BundleChangedInputAndOutputLimit、LateStatisticalEvidenceAndSpoolLimit、StatisticsBoundCardinalityAndAdaptTimeline |
| 成否不明/200/403/404 | 既存TestOutcomeとInvestigation、統合700件の200でもconfirmed_successを禁止 |
| HTML/CSV/JSON/秘密/controls | BundleHostileEvidenceIsSafeAcrossArtifacts、MasksSecretsWithoutChangingOriginalEvidence、EscapesControlCharactersEvenWithSensitiveEvidence |
| 共通集計/言語/navigation/manifest | InvestigationHTMLChaptersNavigationAndSharedRecommendations、RotatedGzipOutOfOrderAndSharedCounts、InventoryAndManifest |
| 大規模資源使用 | report-benchmark、performance.md、performance-data.json |
| offline/既存CLI/output/watch | 全既存テスト、tools/verify-offline.pyのja/en bundleと全hash追加、Linux seccomp、race/fuzz CI |

Phase6では集計型を含む観点の直接/関連リクエストをspoolからunion計数し、署名一致と保持groupの検出数を別単位で合算する。観点の対象母数は既存streamでのrule適用可能性のunionとし、最後に見た集計ruleの値で上書きしない。新しい検出器は追加しない。

## Go版のPR

| Phase | PR | 状態 |
|---|---|---|
| 0 | [#30](https://github.com/mikoto2000/webaudit/pull/30) | マージ済・CI成功・worktree削除済 |
| 1 | [#31](https://github.com/mikoto2000/webaudit/pull/31) | マージ済・CI成功・worktree削除済 |
| 2 | [#32](https://github.com/mikoto2000/webaudit/pull/32) | マージ済・CI成功・worktree削除済 |
| 3 | [#33](https://github.com/mikoto2000/webaudit/pull/33) | マージ済・CI成功・worktree削除済 |
| 4 | [#34](https://github.com/mikoto2000/webaudit/pull/34) | マージ済・CI成功・worktree削除済 |
| 5 | [#35](https://github.com/mikoto2000/webaudit/pull/35) | マージ済・PR/main CI成功・worktree削除済。main CIの既存PowerShell5秒タイムアウトは失敗ジョブの1回の再実行で成功 |
| 6 | [#36](https://github.com/mikoto2000/webaudit/pull/36) | 統合テスト/測定/サンプル生成済。最終CI・マージ状態はPRおよび作業記録を参照 |

Java移植との照合で国DBのみ利用時のASN類似性を評価不能とする前提確認を補正した。`TestCoverageRequiresASNDatabaseForASNSimilarity`が未修正で失敗し、補正後に成功する。国別統計の利用可否とは独立に扱う。
