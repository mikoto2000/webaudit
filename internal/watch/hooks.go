package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Hook struct {
	Executable string
	Args       []string
	ID         string
}
type HookPayload struct {
	IncidentEvent
	HookID         string `json:"hook_id"`
	NotificationID string `json:"notification_id"`
}
type HookResult struct {
	HookID, NotificationID, Error string
	Duration                      time.Duration
	OutputTruncated               bool
}
type HookOptions struct {
	Hooks                  []Hook
	Severity, Events       string
	Timeout                time.Duration
	Concurrency, QueueSize int
	Warn                   func(string)
	Result                 func(HookResult)
}
type hookJob struct {
	hook    Hook
	payload HookPayload
	data    []byte
}
type Dispatcher struct {
	o       HookOptions
	ctx     context.Context
	cancel  context.CancelFunc
	queue   chan hookJob
	wg      sync.WaitGroup
	mu      sync.Mutex
	history map[string]uint64
	dropped atomic.Uint64
}

func NewDispatcher(ctx context.Context, o HookOptions, history map[string]uint64) (*Dispatcher, error) {
	if o.Severity == "" {
		o.Severity = "high"
	}
	if o.Events == "" {
		o.Events = "created"
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Concurrency == 0 {
		o.Concurrency = 1
	}
	if o.QueueSize == 0 {
		o.QueueSize = 128
	}
	if rank(o.Severity) == 0 || (o.Events != "created" && o.Events != "updated" && o.Events != "all") || o.Timeout < time.Millisecond || o.Timeout > time.Hour || o.Concurrency < 1 || o.Concurrency > 32 || o.QueueSize < 1 || o.QueueSize > 4096 || len(o.Hooks) > 16 {
		return nil, fmt.Errorf("invalid hook options")
	}
	for i := range o.Hooks {
		h := &o.Hooks[i]
		if h.Executable == "" || strings.ContainsRune(h.Executable, 0) || len(h.Args) > 64 {
			return nil, fmt.Errorf("invalid hook executable or arguments")
		}
		b, _ := json.Marshal([]any{h.Executable, h.Args})
		if len(b) > 64<<10 {
			return nil, fmt.Errorf("hook configuration too large")
		}
		h.ID = "hook-" + hash(string(b))[:24]
	}
	ctx, cancel := context.WithCancel(ctx)
	d := &Dispatcher{o: o, ctx: ctx, cancel: cancel, queue: make(chan hookJob, o.QueueSize), history: map[string]uint64{}}
	for k, v := range history {
		d.history[k] = v
	}
	if len(o.Hooks) > 0 {
		for i := 0; i < o.Concurrency; i++ {
			d.wg.Add(1)
			go d.worker()
		}
	}
	return d, nil
}
func (d *Dispatcher) warn(s string) {
	if d.o.Warn != nil {
		d.o.Warn(s)
	}
}
func (d *Dispatcher) Dispatch(v IncidentEvent) int {
	if rank(v.Severity) < rank(d.o.Severity) || d.ctx.Err() != nil {
		return 0
	}
	if v.EventType != "incident_created" && v.EventType != "incident_updated" {
		return 0
	}
	if v.EventType == "incident_updated" && !v.Notify {
		return 0
	}
	if d.o.Events != "all" && v.EventType != "incident_"+d.o.Events {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, h := range d.o.Hooks {
		key := v.IncidentID + "/" + h.ID
		if d.history[key] >= v.Revision {
			continue
		}
		p := HookPayload{IncidentEvent: v, HookID: h.ID, NotificationID: "notification-" + hash(fmt.Sprintf("%s/%d/%s", v.IncidentID, v.Revision, h.ID))[:32]}
		b, err := json.Marshal(p)
		if err != nil || len(b) > 64<<10 {
			d.dropped.Add(1)
			d.warn("hook payload exceeds JSON size limit; notification dropped")
			continue
		}
		b = append(b, '\n')
		select {
		case d.queue <- hookJob{h, p, b}:
			d.history[key] = v.Revision
			n++
		default:
			d.dropped.Add(1)
			d.warn("hook queue full; notification dropped")
		}
	}
	return n
}
func (d *Dispatcher) History() map[string]uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := map[string]uint64{}
	for k, v := range d.history {
		m[k] = v
	}
	return m
}
func (d *Dispatcher) Prune(incidents map[string]*IncidentState) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.history {
		id, _, _ := strings.Cut(k, "/")
		if _, ok := incidents[id]; !ok {
			delete(d.history, k)
		}
	}
}
func (d *Dispatcher) Dropped() uint64 { return d.dropped.Load() }
func (d *Dispatcher) Close()          { d.cancel(); d.wg.Wait() }
func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case j := <-d.queue:
			if d.ctx.Err() != nil {
				return
			}
			r := d.execute(j)
			if r.Error != "" {
				d.warn(fmt.Sprintf("hook failed: %s %s: %s", r.HookID, r.NotificationID, r.Error))
			}
			if d.o.Result != nil {
				d.o.Result(r)
			}
		}
	}
}

// cappedOutput drains all bytes so a noisy child cannot block, while retaining only
// a fixed-size prefix. Output contents are never printed (they can contain secrets).
type cappedOutput struct {
	data      []byte
	truncated bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (16 << 10) - len(w.data)
	if len(p) > remaining {
		p = p[:remaining]
		w.truncated = true
	}
	w.data = append(w.data, p...)
	return n, nil
}
func (d *Dispatcher) execute(j hookJob) HookResult {
	start := time.Now()
	r := HookResult{HookID: j.hook.ID, NotificationID: j.payload.NotificationID}
	ctx, cancel := context.WithTimeout(d.ctx, d.o.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, j.hook.Executable, j.hook.Args...)
	cmd.Stdin = bytes.NewReader(j.data)
	stdout, stderr := &cappedOutput{}, &cappedOutput{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 250 * time.Millisecond
	cleanup, err := startHook(cmd)
	if err == nil {
		err = cmd.Wait()
		cleanup()
	}
	if err != nil {
		r.Error = err.Error()
	}
	if ctx.Err() != nil {
		r.Error = ctx.Err().Error()
	}
	r.Duration = time.Since(start)
	r.OutputTruncated = stdout.truncated || stderr.truncated
	return r
}
