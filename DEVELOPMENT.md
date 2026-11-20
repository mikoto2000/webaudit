# 開発者向けガイド

利用方法と対応範囲は[README.md](README.md)を参照してください。

## 開発環境とビルド

開発環境はGo 1.27.4。公式の安定版情報とSHA-256を確認して選定しました。MMDBリーダーの依存ソースとライセンスは`vendor/`に保存し、ネットワークなしでビルドできます。

```sh
go test ./...
go vet ./...
go build -trimpath -buildvcs=false -o dist/webaudit ./cmd/webaudit
```

Windowsでのビルド例:

```powershell
go build -trimpath -buildvcs=false -o dist/webaudit-windows-amd64.exe ./cmd/webaudit
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -buildvcs=false -o dist/webaudit-linux-amd64 ./cmd/webaudit
```

## 開発用評価

```sh
go run ./tools/evaluate
go run ./tools/benchmark -lines 1000000
go run ./tools/benchmark -lines 1000000 -padding 3000
go test ./audit -run='^$' -fuzz=FuzzParse -fuzztime=10s -parallel=4
```

## 調査・設計資料

[競合調査](docs/competitor-analysis.md)、[ルール台帳](docs/rule-inventory.md)、[検知設計](docs/detection-design.md) を参照してください。外部データリストは無条件に移植せず、未対応の理由を台帳に記録しています。
