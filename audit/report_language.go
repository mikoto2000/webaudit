package audit

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Catalogs apply to presentation only. Evidence and machine-report values are
// never rewritten, and all translated strings retain html/template escaping.
//
//go:embed locales/ja.json
var japaneseMessages []byte

//go:embed locales/investigation_en.json
var englishInvestigation []byte

func messageCatalog(data []byte) map[string]string {
	var messages map[string]string
	if err := json.Unmarshal(data, &messages); err != nil {
		panic(err)
	}
	return messages
}

var reportJapanese = messageCatalog(japaneseMessages)
var reportEnglish = messageCatalog(englishInvestigation)

type reportTranslator struct{ language string }

var missingFieldMessage = regexp.MustCompile(`^Missing ([a-z_]+) in ([0-9]+) parsed requests reduces related detection coverage$`)
var observationMessage = regexp.MustCompile(`^([0-9]+) observations in overlapping five-minute event-time window; diversity bounded at 64$`)
var geoDatabaseMessage = regexp.MustCompile(`^GeoIP (country|asn) database (".*"): (.*); automatic database ignored$`)
var geoLookupMessage = regexp.MustCompile(`^GeoIP (country|asn) lookup failed: (.*)$`)
var directoryMessage = regexp.MustCompile(`^directory (.*): (.*)$`)

func (tr reportTranslator) text(value any) string {
	s := fmt.Sprint(value)
	if tr.language == "en" {
		if translated, ok := reportEnglish[s]; ok {
			return translated
		}
		return s
	}
	if translated, ok := reportJapanese[s]; ok {
		return translated
	}
	if m := missingFieldMessage.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("解析済みの%s件の要求で%sが欠落し、関連する検出範囲が狭まっています", m[2], tr.text(m[1]))
	}
	if m := observationMessage.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("重複する5分間のイベント時刻区分で%s件を観測。異なる値は最大64件まで保持", m[1])
	}
	return s
}

func (tr reportTranslator) outcome(s string) string {
	switch s {
	case "unknown":
		return tr.text("Unknown outcome")
	case "confirmed_success":
		return tr.text("Confirmed success")
	case "possible_success":
		return tr.text("Possible success")
	case "likely_failed":
		return tr.text("Likely failed")
	case "confirmed_failure":
		return tr.text("Confirmed failure")
	}
	return tr.text(s)
}

// External errors may contain OS/library diagnostics and paths. Translate known
// WebAudit messages, retaining those original details instead of guessing at them.
func (tr reportTranslator) diagnostic(s string) string {
	if s == "" || tr.language == "en" {
		return tr.text(s)
	}
	if translated, ok := tr.knownDiagnostic(s); ok {
		return translated
	}
	// File/line diagnostics have an original path prefix. Translate only the
	// diagnostic suffix, leaving paths (including Windows drive letters) intact.
	for at := 0; at < len(s); {
		i := strings.Index(s[at:], ": ")
		if i < 0 {
			break
		}
		at += i + 2
		if translated, ok := tr.knownDiagnostic(s[at:]); ok {
			return s[:at] + translated
		}
	}
	return "診断情報（原文）: " + s
}

func (tr reportTranslator) knownDiagnostic(s string) (string, bool) {
	if translated := tr.text(s); translated != s {
		return translated, true
	}
	if m := geoDatabaseMessage.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("GeoIP %s DB %sを利用できないため、自動検出したDBを無視しました（詳細は原文）: %s", tr.text(m[1]), m[2], m[3]), true
	}
	if m := geoLookupMessage.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("GeoIP %sの検索に失敗しました（詳細は原文）: %s", tr.text(m[1]), m[2]), true
	}
	if m := directoryMessage.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("ディレクトリ %sの読み込みエラー（詳細は原文）: %s", m[1], m[2]), true
	}
	for _, pair := range [][2]string{
		{"Invalid error log timezone: ", "エラーログのタイムゾーンが不正です（詳細は原文）: "},
		{"Skipped non-regular input: ", "通常ファイルではない入力を読み飛ばしました: "},
		{"Managed GeoIP unavailable; analysis continues without automatic GeoIP: ", "管理GeoIPを利用できないため、自動GeoIPなしで解析を続行します（詳細は原文）: "},
		{"ambiguous JSON field ", "解釈が競合するJSONフィールド: "},
		{"duplicate JSON field ", "重複したJSONフィールド: "},
		{"invalid JSON: ", "不正なJSON（詳細は原文）: "},
		{"custom regex: ", "カスタム正規表現のエラー（詳細は原文）: "},
	} {
		if rest, ok := strings.CutPrefix(s, pair[0]); ok {
			return pair[1] + rest, true
		}
	}
	return "", false
}
