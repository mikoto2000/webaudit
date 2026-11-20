package main

import (
	"encoding/json"
	"fmt"
	"os"
	"webaudit/audit"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: webaudit LOG...")
		os.Exit(2)
	}
	r := audit.Stream(os.Args[1:], audit.Options{}, func(audit.Event) {})
	_ = json.NewEncoder(os.Stdout).Encode(r)
	if r.Partial {
		os.Exit(1)
	}
}
