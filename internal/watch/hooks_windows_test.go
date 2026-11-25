//go:build windows

package watch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHookPowerShellFileArguments(t *testing.T) {
	exe, e := exec.LookPath("powershell.exe")
	if e != nil {
		t.Skip("PowerShell not installed")
	}
	d := t.TempDir()
	script := filepath.Join(d, "notify with spaces.ps1")
	output := filepath.Join(d, "result with spaces.json")
	put(t, script, "$ErrorActionPreference='Stop'\n$eventData=[Console]::In.ReadToEnd() | ConvertFrom-Json\n$eventData | ConvertTo-Json -Compress -Depth 8 | Set-Content -LiteralPath $args[0] -Encoding UTF8\n")
	ch := make(chan HookResult, 1)
	// This checks argument handling, not startup latency. A cold PowerShell on
	// a shared Windows runner can take more than five seconds to initialize.
	dispatcher, e := NewDispatcher(context.Background(), HookOptions{Hooks: []Hook{{Executable: exe, Args: []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, output}}}, Timeout: 30 * time.Second, Result: func(r HookResult) { ch <- r }}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer dispatcher.Close()
	dispatcher.Dispatch(hookEvent())
	select {
	case r := <-ch:
		if r.Error != "" {
			t.Fatal(r)
		}
	case <-time.After(35 * time.Second):
		t.Fatal("PowerShell hook result timeout")
	}
	b, e := os.ReadFile(output)
	if e != nil || !strings.Contains(string(b), "evt-test") {
		t.Fatal(string(b), e)
	}
}
