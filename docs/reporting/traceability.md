# 要求と実装の対応表

要求の原文は[requirements.md](requirements.md)。各章の列挙項目は該当する行の範囲に含む。完了時には根拠となるモデル・テスト・成果物を更新し、未対応を完了と表現しない。

| 要求 | 現行 | 実装phase | 検証根拠/完成状態 |
|---|---|---|---|
| §1–2 オフライン・再現性・互換性・batch | 部分 | 全phase | 現行設計を維持。設計のみ |
| §3 第1章 基本情報・結果サマリー | 部分 | 1,3,4,5 | 任意metadata、共通model、計数定義。未実装 |
| 第2章 対象・inventory・対象外 | 部分 | 1,5 | 原本hash/format/field/診断。未実装 |
| 第3章 実装に即した方法 | 部分 | 1,2,5 | ルール・制限と実行条件。未実装 |
| 第4章 severity/confidence/outcomeの分離 | 部分 | 2,5 | 未評価confidenceはunknown。未実装 |
| 第5章 基礎・時系列・Geo統計と全グラフ | 部分 | 4,5 | 共通分母・件数属性。未実装 |
| 第6章 全観点・全ルールcoverage | 未対応 | 2,5 | 支援なし/未評価/部分/hitを独立。未実装 |
| 第7章 事案一覧・engine別集計 | 部分 | 3,5 | 一意requestと重複検出を区別。未実装 |
| 第8章 詳細・事実/推定・証拠・案内 | 部分 | 3,5 | 現行investigation再利用。未実装 |
| 第9章 根拠ある総合評価 | 未対応 | 4,5 | 不存在/成功の断定禁止。未実装 |
| 第10章 一般制約と発生制約 | 部分 | 1,2,5 | completenessとwarnings。未実装 |
| 第11章 事案に応じた推奨対応 | 部分 | 3,5 | finding参照・priority・種類。未実装 |
| §4 不審/関連全件・遅延検出・変更確認 | 未対応 | 3 | bounded spool・request ID。未実装 |
| §5 共通modelとstable ID | 部分 | 1–5 | Request/Detection/Finding別。未実装 |
| §6 一式出力とmanifest・全hash | 未対応 | 1,3–5 | report-dir専用モード。未実装 |
| §7 日英・目次・navigation・offline・印刷 | 部分 | 5 | HTML/escape/graph。未実装 |
| §8 全出力の安全性・資源制限 | 部分 | 1,3,5,6 | 注入/paths/上限/排他。未実装 |
| §9 正確性・完全性・集計関係 | 部分 | 1–6 | 分母・重複・欠損・下限。未実装 |
| §10 phase順序 | 新規 | 0–6 | Go完了後Java。Phase 0設計作成 |
| §11 TDD/worktree/PR/CI/merge/cleanup | 新規 | 全phase | 作業記録とPRで追跡 |
| §12 必須テスト全項目 | 部分 | 1–6 | 既存回帰＋新規契約テスト。未実装 |
| §13 完了条件と§14 最終報告 | 未対応 | 6/Java完了時 | 本表・PR/測定/sampleで照合。未完了 |


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
