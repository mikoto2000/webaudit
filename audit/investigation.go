package audit

import "sort"

// Investigation describes evidence to seek, never evidence observed by WebAudit.
type Investigation struct {
	Category        string   `json:"category"`
	WhyUnknown      string   `json:"why_unknown"`
	WhereToCheck    []string `json:"where_to_check"`
	SuccessEvidence string   `json:"success_evidence"`
	FailureEvidence string   `json:"failure_evidence"`
}

func investigationFor(categories []string) []Investigation {
	keys := append([]string(nil), categories...)
	sort.Strings(keys)
	if len(keys) == 0 {
		keys = []string{"unknown"}
	}
	var out []Investigation
	for _, category := range keys {
		if len(out) > 0 && out[len(out)-1].Category == category {
			continue
		}
		g := guidanceFor(category)
		g.Category = category
		out = append(out, g)
	}
	return out
}

func guidanceFor(category string) Investigation {
	switch category {
	case "sqli", "nosqli", "ldap_injection", "xpath_injection":
		return Investigation{
			WhyUnknown:      "アクセスログには、バックエンドで実行された問い合わせと取得・変更されたデータが記録されていません。",
			WhereToCheck:    []string{"アプリケーションの処理・エラーログと当時の応答記録", "対象のDB・ディレクトリサービス・XML検索処理の監査ログ"},
			SuccessEvidence: "対象要求の入力によって意図しない問い合わせが実行され、データ取得・変更や認証回避が起きた記録。",
			FailureEvidence: "対象要求が問い合わせ実行前に拒否された記録、または入力が値として扱われ、意図しない問い合わせや結果が生じなかった処理記録。",
		}
	case "command_injection", "shellshock", "ssti", "deserialization", "log4shell", "spring4shell", "struts_ognl":
		return Investigation{
			WhyUnknown:      "ペイロードが届いたことだけでは、式の評価・デシリアライズ・コードやコマンドの実行を確認できません。",
			WhereToCheck:    []string{"対象アプリ・ランタイムの処理ログ、当時の応答記録", "ホスト監査・EDRのプロセス親子関係、ファイル変更、DNS・外向き通信の記録"},
			SuccessEvidence: "対象要求に対応する意図しない式の評価結果、コード実行、子プロセス生成やファイル変更の記録。外向き通信だけが見つかった場合は、その通信の発生までが確認範囲で、コード実行の確定には追加証拠が必要です。",
			FailureEvidence: "対象要求が危険な処理に入る前に拒否された記録、または入力が実行・評価されずに処理されたことを示す記録。",
		}
	case "sensitive_file", "lfi_traversal", "null_byte", "sensitive":
		return Investigation{
			WhyUnknown:      "HTTPステータスや応答サイズだけでは、対象ファイルの内容が返されたか、読み込み・実行されたか判断できません。",
			WhereToCheck:    []string{"当時の応答本文、アプリのファイル読み込み記録、ホストのファイルアクセス監査", "Webサーバー・プロキシのルーティング設定と、共通エラーページの当時の記録"},
			SuccessEvidence: "対象要求への応答に本来公開しないファイル内容が含まれた記録、または不正なファイル読み込み・実行の記録。",
			FailureEvidence: "対象要求がファイルアクセス前に拒否された記録、または対象ファイルを読み込まず情報を含まない応答を返した処理記録。",
		}
	case "rfi", "ssrf", "xxe":
		return Investigation{
			WhyUnknown:      "アクセスログには、サーバー側での外部リソース取得・外部実体展開や内部サービスへの到達結果がありません。",
			WhereToCheck:    []string{"アプリ・XMLパーサーの処理ログと当時の応答本文", "DNS・プロキシ・外向き通信ログ、要求先サービスの受信記録、ファイルアクセス監査"},
			SuccessEvidence: "対象要求を原因とする意図しない内部・外部リソースの取得、外部実体展開、ファイル読み出しや取り込んだコードの実行記録。",
			FailureEvidence: "対象要求のリソース取得・実体展開が処理前に拒否された記録、または該当処理が無効で実行されなかった記録。",
		}
	case "webshell":
		return Investigation{
			WhyUnknown:      "疑わしいURLへのアクセスだけでは、Webシェルの設置や実行を確認できません。",
			WhereToCheck:    []string{"公開ディレクトリ・アップロード領域の当時のファイルと変更履歴", "Webアプリ・ホスト監査・EDRの実行記録、プロセス親子関係と外向き通信"},
			SuccessEvidence: "不正なWebシェルの設置記録、または対象要求によるシェル処理・コマンド実行の記録。設置と実行は区別してください。",
			FailureEvidence: "対象要求が実行前に拒否された記録、または当時そのパスに実行可能なWebシェルがなく、別の実行先にも転送されなかった処理記録。",
		}
	case "xss":
		return Investigation{
			WhyUnknown:      "アクセスログだけでは、入力が応答や保存データにどう埋め込まれ、ブラウザーで実行されたか確認できません。",
			WhereToCheck:    []string{"当時の応答HTML・保存データと、その表示先の記録", "対象ブラウザーの実行・通信記録、CSPレポート"},
			SuccessEvidence: "対象入力に由来するスクリプトが対象画面で実行された記録。反射・保存されただけでは実行の確定にはなりません。",
			FailureEvidence: "対象入力が拒否された記録、または該当表示箇所で実行されない形にエスケープされた記録。CSPの遮断記録はその実行試行について確認してください。",
		}
	case "crlf_injection", "open_redirect":
		return Investigation{
			WhyUnknown:      "アクセスログには応答ヘッダーや遷移先がなく、意図しないヘッダー追加やリダイレクトを確認できません。",
			WhereToCheck:    []string{"当時の応答ヘッダー（Location等）とプロキシ・アプリの処理記録", "必要に応じてブラウザーの遷移・通信記録"},
			SuccessEvidence: "対象入力によって意図しない応答ヘッダー・応答分割、または許可されていない遷移先へのLocationが生成された記録。実際の遷移はブラウザー側で確認してください。",
			FailureEvidence: "対象入力が拒否された記録、またはヘッダー改行が除去され、遷移先の検証で意図しない応答が防がれた記録。",
		}
	case "access_bypass", "auth", "login":
		return Investigation{
			WhyUnknown:      "HTTPステータスだけでは、認証成立・権限判定や保護対象への実際のアクセスを確認できません。",
			WhereToCheck:    []string{"認証・セッション発行・認可の監査ログ", "対象アカウントの操作履歴、保護対象へのアクセス記録と当時の応答本文"},
			SuccessEvidence: "不正な認証成立・セッション発行、または権限のない主体が保護されたデータや操作へ到達した記録。正規利用と区別してください。",
			FailureEvidence: "対象要求の認証・認可が拒否され、保護対象の処理や情報返却が行われなかった記録。",
		}
	case "rate", "burst", "WS-ip", "WS-hour":
		return Investigation{
			WhyUnknown:      "アクセス量の多さだけでは、正規の集中アクセスか攻撃か、サービスへの影響があったか判断できません。",
			WhereToCheck:    []string{"同時間帯の可用性・応答時間・CPU・メモリー・接続数の監視記録", "WAF・レート制限・ロードバランサーの記録と正規利用・負荷試験の予定"},
			SuccessEvidence: "対象の大量要求によって資源枯渇や可用性低下が起きたと関連付けられる監視・処理記録。",
			FailureEvidence: "対象要求が制限・遮断され、十分な監視範囲でサービス影響が生じなかったことを示す記録。正規アクセスだった場合は誤検知として区別してください。",
		}
	case "WS-size", "WS-url-size":
		return Investigation{
			WhyUnknown:      "応答サイズの増加だけでは、情報流出か正規の大きな応答か区別できません。",
			WhereToCheck:    []string{"当時の応答本文、アプリの出力・ダウンロード監査ログ", "対象データのアクセス権と、同じURLの正規応答・変更履歴"},
			SuccessEvidence: "対象要求に対し、権限のない相手に機密データを返したことがわかる応答・監査記録。",
			FailureEvidence: "対象要求に返した内容と認可記録から、機密データの不正な返却がなかったと確認できる記録。",
		}
	case "cve_probe", "iis_aspnet", "recon_probe", "scanner", "method", "unusual_protocol", "404", "paths", "ua", "multi", "WS-errors":
		return Investigation{
			WhyUnknown:      "探索・異常な要求やエラーの検出は、脆弱性の存在や悪用の成功を示しません。",
			WhereToCheck:    []string{"対象ホストの当時の製品バージョン・設定、ルーティングとWAF・アプリの処理ログ", "同時間帯の後続要求、応答本文、認証・ファイル変更・プロセス実行の記録"},
			SuccessEvidence: "対象要求による非公開情報の取得、不正な状態変更やコード実行など、具体的な影響を示す記録。",
			FailureEvidence: "対象要求が処理前に拒否された記録、または対象機能が存在せず別の処理先にも到達しなかったことを示す記録。",
		}
	default:
		return Investigation{
			WhyUnknown:      "アクセスログには、要求がサーバー内部でどう処理され、どの内容が返されたかの証拠が不足しています。",
			WhereToCheck:    []string{"元ログのファイル・行番号、当時の応答記録、プロキシ・アプリ・認証ログ", "対象ホストの監査記録（ファイル変更・プロセス実行・外向き通信）"},
			SuccessEvidence: "対象要求と関連付けられる情報漏えい、不正操作や実行など、攻撃目的が達成されたことを示す証拠。",
			FailureEvidence: "対象要求が目的の処理に到達する前に拒否されたこと、または意図しない結果が生じなかったことを示す処理記録。",
		}
	}
}
