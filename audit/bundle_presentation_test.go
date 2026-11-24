package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestInvestigationHTMLChaptersNavigationAndSharedRecommendations(t *testing.T) {
	for _, lang := range []string{"ja", "en"} {
		t.Run(lang, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "report")
			r, err := GenerateBundle([]string{"../examples/sample.log"}, target, Options{}, BundleOptions{Language: lang, Title: "<script>title</script>"})
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(target, "report.html"))
			if err != nil {
				t.Fatal(err)
			}
			html := string(data)
			for i := 1; i <= 11; i++ {
				if !strings.Contains(html, fmt.Sprintf(`id="chapter-%d"`, i)) || !strings.Contains(html, fmt.Sprintf(`href="#chapter-%d"`, i)) {
					t.Fatal("chapter missing", i)
				}
			}
			if strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;title&lt;/script&gt;") || !strings.Contains(html, "<meter") || !strings.Contains(html, "@media print") {
				t.Fatal("unsafe or missing visual/print output")
			}
			if lang == "ja" && !strings.Contains(html, "第11章 推奨対応") {
				t.Fatal("missing Japanese title")
			}
			if lang == "en" && !strings.Contains(html, "11. Recommended actions") {
				t.Fatal("missing English title")
			}
			if len(r.Recommendations) == 0 || r.Summary.TotalRequests != r.Statistics.TotalRequests {
				t.Fatal("missing common summary/recommendations")
			}
			ids := map[string]bool{}
			for _, m := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
				if ids[m[1]] {
					t.Fatal("duplicate anchor", m[1])
				}
				ids[m[1]] = true
			}
			for _, m := range regexp.MustCompile(`href="#([^"]+)"`).FindAllStringSubmatch(html, -1) {
				if !ids[m[1]] {
					t.Fatal("broken navigation", m[1])
				}
			}
			rows := bundleCSV(t, filepath.Join(target, "recommendations.csv"))
			if len(rows) != len(r.Recommendations) {
				t.Fatal("recommendation model differs from CSV")
			}
		})
	}
}
func TestBundleMasksSecretsWithoutChangingOriginalEvidence(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "access.log")
	raw := `192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /.env?token=TOPSECRET HTTP/1.1" 404 0 "-" "Browser"`
	if err := os.WriteFile(input, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "masked")
	r, err := GenerateBundle([]string{input}, target, Options{}, BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.MaskingEnabled {
		t.Fatal("masking not disclosed")
	}
	err = filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "TOPSECRET") {
			t.Fatal("secret exposed", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(input)
	if !strings.Contains(string(original), "TOPSECRET") {
		t.Fatal("original source modified")
	}
	clear := filepath.Join(dir, "sensitive")
	_, err = GenerateBundle([]string{input}, clear, Options{}, BundleOptions{IncludeSensitiveEvidence: true})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(clear, "suspicious-requests.csv"))
	if !strings.Contains(string(data), "TOPSECRET") {
		t.Fatal("explicit sensitive export not respected")
	}
}
