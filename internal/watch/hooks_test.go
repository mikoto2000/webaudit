package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHookChild(t *testing.T) {
	if os.Getenv("WEBAUDIT_HOOK_TEST") != "1" {
		return
	}
	at := 0
	for i, s := range os.Args {
		if s == "--" {
			at = i + 1
			break
		}
	}
	if at == 0 {
		os.Exit(3)
	}
	args := os.Args[at:]
	switch args[0] {
	case "echo":
		b, _ := io.ReadAll(os.Stdin)
		v := map[string]any{"stdin": string(b), "args": args[2:]}
		b, _ = json.Marshal(v)
		if os.WriteFile(args[1], b, 0600) != nil {
			os.Exit(4)
		}
	case "fail":
		fmt.Fprint(os.Stderr, strings.Repeat("x", 100000))
		os.Exit(7)
	case "sleep":
		time.Sleep(60 * time.Second)
	case "gate":
		os.WriteFile(args[1]+".ready", []byte("ready"), 0600)
		for {
			if _, e := os.Stat(args[1] + ".release"); e == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	case "tree":
		c := exec.Command(os.Args[0], "-test.run=^TestHookChild$", "--", "grandchild", args[1])
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if c.Start() != nil {
			os.Exit(5)
		}
		os.WriteFile(args[1]+".ready", []byte("ready"), 0600)
		time.Sleep(60 * time.Second)
	case "grandchild":
		time.Sleep(time.Second)
		os.WriteFile(args[1], []byte("survived"), 0600)
	}
	os.Exit(0)
}
func hook(mode string, args ...string) Hook {
	return Hook{Executable: os.Args[0], Args: append([]string{"-test.run=^TestHookChild$", "--", mode}, args...)}
}
func hookEvent() IncidentEvent {
	return IncidentEvent{SchemaVersion: 1, IncidentID: "inc-test", Revision: 1, EventType: "incident_created", EventID: "evt-test", Severity: "high", Outcome: "unknown", Notify: true}
}
func result(t *testing.T, ch <-chan HookResult) HookResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("hook result timeout")
		return HookResult{}
	}
}
func TestHookJSONLiteralArgsAndDedup(t *testing.T) {
	t.Setenv("WEBAUDIT_HOOK_TEST", "1")
	p := filepath.Join(t.TempDir(), "output with spaces.json")
	ch := make(chan HookResult, 2)
	h := hook("echo", p, `$(touch BAD); & <script>`, "a b", `quote"slash\`)
	d, e := NewDispatcher(context.Background(), HookOptions{Hooks: []Hook{h}, Result: func(r HookResult) { ch <- r }}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	v := hookEvent()
	if d.Dispatch(v) != 1 || d.Dispatch(v) != 0 {
		t.Fatal("dedup")
	}
	r := result(t, ch)
	if r.Error != "" {
		t.Fatal(r)
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var got struct {
		Stdin string
		Args  []string
	}
	if e = json.Unmarshal(b, &got); e != nil {
		t.Fatal(e)
	}
	var payload HookPayload
	if e = json.Unmarshal([]byte(got.Stdin), &payload); e != nil {
		t.Fatal(e)
	}
	if payload.NotificationID == "" || payload.EventID != v.EventID || len(got.Args) != 3 || got.Args[0] != h.Args[len(h.Args)-3] {
		t.Fatal(got, payload)
	}
	restored, e := NewDispatcher(context.Background(), HookOptions{Hooks: []Hook{h}}, d.History())
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	if restored.Dispatch(v) != 0 {
		t.Fatal("restart duplicate")
	}
}
func TestHookFailureTimeoutFiltersAndQueue(t *testing.T) {
	t.Setenv("WEBAUDIT_HOOK_TEST", "1")
	ch := make(chan HookResult, 16)
	d, e := NewDispatcher(context.Background(), HookOptions{Hooks: []Hook{hook("fail"), hook("sleep")}, Timeout: 100 * time.Millisecond, Concurrency: 1, QueueSize: 2, Events: "all", Result: func(r HookResult) { ch <- r }}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	v := hookEvent()
	v.Severity = "medium"
	if d.Dispatch(v) != 0 {
		t.Fatal("severity")
	}
	v.Severity = "high"
	v.EventType = "incident_updated"
	v.Notify = false
	if d.Dispatch(v) != 0 {
		t.Fatal("count-only")
	}
	v.Notify = true
	if d.Dispatch(v) != 2 {
		t.Fatal("multiple hooks")
	}
	a, b := result(t, ch), result(t, ch)
	if a.Error == "" || b.Error == "" {
		t.Fatal(a, b)
	}
	for i := 2; i < 20; i++ {
		v.Revision = uint64(i)
		d.Dispatch(v)
	}
	if d.Dropped() == 0 {
		t.Fatal("queue unbounded")
	}
}
func TestHookCancellationKillsDescendants(t *testing.T) {
	t.Setenv("WEBAUDIT_HOOK_TEST", "1")
	marker := filepath.Join(t.TempDir(), "child-marker")
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan HookResult, 1)
	d, e := NewDispatcher(ctx, HookOptions{Hooks: []Hook{hook("tree", marker)}, Timeout: 10 * time.Second, Result: func(r HookResult) { ch <- r }}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	d.Dispatch(hookEvent())
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, e = os.Stat(marker + ".ready"); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tree did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	result(t, ch)
	time.Sleep(1200 * time.Millisecond)
	if _, e = os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("descendant survived", e)
	}
}

func TestHookHistoryPrunesRemovedHooks(t *testing.T) {
	d, e := NewDispatcher(context.Background(), HookOptions{}, map[string]uint64{"inc-test/removed-hook": 1})
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	d.Prune(map[string]*IncidentState{"inc-test": {}})
	if len(d.History()) != 0 {
		t.Fatal("obsolete hook history retained")
	}
}

func TestHookConcurrencyLimit(t *testing.T) {
	t.Setenv("WEBAUDIT_HOOK_TEST", "1")
	for _, workers := range []int{1, 2} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			d := t.TempDir()
			a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
			ch := make(chan HookResult, 2)
			dispatcher, e := NewDispatcher(context.Background(), HookOptions{Hooks: []Hook{hook("gate", a), hook("gate", b)}, Concurrency: workers, Result: func(r HookResult) { ch <- r }}, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer dispatcher.Close()
			dispatcher.Dispatch(hookEvent())
			wait := func(p string) {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, e := os.Stat(p + ".ready"); e == nil {
						return
					}
					if time.Now().After(deadline) {
						t.Fatal("hook did not start", p)
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			if workers == 1 {
				wait(a)
				time.Sleep(30 * time.Millisecond)
				if _, e := os.Stat(b + ".ready"); !os.IsNotExist(e) {
					t.Fatal("concurrency exceeded")
				}
				put(t, a+".release", "")
				wait(b)
			} else {
				wait(a)
				wait(b)
				put(t, a+".release", "")
			}
			put(t, b+".release", "")
			for i := 0; i < 2; i++ {
				if r := result(t, ch); r.Error != "" {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestHookExecutableWithSpaces(t *testing.T) {
	t.Setenv("WEBAUDIT_HOOK_TEST", "1")
	d := t.TempDir()
	path := filepath.Join(d, "hook executable with spaces.exe")
	src, e := os.Open(os.Args[0])
	if e != nil {
		t.Fatal(e)
	}
	dst, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		src.Close()
		t.Fatal(e)
	}
	_, e = io.Copy(dst, src)
	src.Close()
	dst.Close()
	if e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(d, "payload.json")
	h := hook("echo", output, "literal value")
	h.Executable = path
	ch := make(chan HookResult, 1)
	dispatcher, e := NewDispatcher(context.Background(), HookOptions{Hooks: []Hook{h}, Result: func(r HookResult) { ch <- r }}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer dispatcher.Close()
	dispatcher.Dispatch(hookEvent())
	if r := result(t, ch); r.Error != "" {
		t.Fatal(r)
	}
	if _, e = os.Stat(output); e != nil {
		t.Fatal(e)
	}
}
