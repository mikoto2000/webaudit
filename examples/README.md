Synthetic demonstration only. The 2xx sensitive-resource sequence suggests exposure but does not confirm it; the SQLi 500 remains unknown. All report formats use portable source references to examples/sample.log.

HTMLのサンプルは既定の日本語です。英語で生成する場合は`webaudit examples/sample.log --lang en -o report-en.html`を実行してください。元ログやルールIDは翻訳しません。

## GeoIP合成例

`geoip-sample-report.html`と`geoip-sample.log`は合成MMDBによる例です。公開IPも架空の国・ASNへ割り当てており、現実の所在地・運営者を示しません。再生成はリポジトリルートで`go run ./tools/geoip-example`。実DBや通信は不要です。
