// Package diagnostics provides a small, cooperative scenario runner for
// development diagnostics. It contains no native bindings or device protocol.
package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"runtime"
	"sync"
	"time"
)

// Status is a scenario's evidence-based result.
type Status string

const (
	Pass         Status = "PASS"
	Fail         Status = "FAIL"
	Skip         Status = "SKIP"
	Inconclusive Status = "INCONCLUSIVE"
)

// Scenario defines one bounded check. Run and cleanup callbacks must honor
// their contexts; the runner never abandons a callback in a detached goroutine.
type Scenario struct {
	ID           string
	Layer        string
	Mode         Mode
	Requirements []string
	Timeout      time.Duration
	Run          func(context.Context, *Scope) error
	// Validate checks the evidence after cleanup, before PASS is finalized.
	// It must be a bounded, read-only check without device I/O.
	Validate func(Result) error
}

// Mode identifies an execution opt-in. The zero value runs deterministic checks.
type Mode string

const (
	Deterministic Mode = ""
	Hardware      Mode = "hardware"
	Strict        Mode = "strict"
	Interactive   Mode = "interactive"
)

// Options selects available requirements and the per-scenario cleanup budget.
type Options struct {
	Capabilities   map[string]bool
	EnabledModes   map[Mode]bool
	CleanupTimeout time.Duration
}

// Environment describes the execution environment without device identifiers.
type Environment struct {
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	GoVersion        string `json:"go_version"`
	GoroutinesBefore int    `json:"goroutines_before"`
	GoroutinesAfter  int    `json:"goroutines_after"`
}

// NativeError records native codes. Message must never contain device serials
// or report contents; diagnostic scenarios own this restriction.
type NativeError struct {
	Operation string `json:"operation"`
	Domain    string `json:"domain"`
	Code      uint64 `json:"code"`
	Message   string `json:"message,omitempty"`
}

// Cleanup records whether every registered cleanup callback was attempted.
type Cleanup struct {
	Complete bool          `json:"complete"`
	Duration time.Duration `json:"duration_ns"`
	Errors   []string      `json:"errors,omitempty"`
}

// Result is one scenario's machine-readable evidence and cleanup outcome.
type Result struct {
	ScenarioID   string            `json:"scenario_id"`
	Layer        string            `json:"layer,omitempty"`
	Mode         Mode              `json:"mode,omitempty"`
	Status       Status            `json:"status"`
	Requirements []string          `json:"requirements,omitempty"`
	StartedAt    time.Time         `json:"started_at"`
	Duration     time.Duration     `json:"duration_ns"`
	Reason       string            `json:"reason,omitempty"`
	Cleanup      Cleanup           `json:"cleanup"`
	Counters     map[string]uint64 `json:"counters,omitempty"`
	Facts        map[string]bool   `json:"facts,omitempty"`
	NativeErrors []NativeError     `json:"native_errors,omitempty"`
}

// Report groups scenario records with a versioned execution environment.
type Report struct {
	SchemaVersion int           `json:"schema_version"`
	Environment   Environment   `json:"environment"`
	StartedAt     time.Time     `json:"started_at"`
	Duration      time.Duration `json:"duration_ns"`
	Results       []Result      `json:"results"`
}

// Scope collects bounded, non-secret evidence and LIFO cleanup callbacks.
// Evidence methods are safe to call from scenario helper goroutines. Scenarios
// must join their helpers before returning; a report owns independent evidence
// copies and cannot be modified by a late helper.
type Scope struct {
	mu           sync.Mutex
	counters     map[string]uint64
	facts        map[string]bool
	nativeErrors []NativeError
	cleanup      []func(context.Context) error
}

// Counter records the final value of a named native or lifecycle counter.
func (scope *Scope) Counter(name string, value uint64) {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	scope.counters[name] = value
}

// Fact records a Boolean observation, rather than an inferred timing claim.
func (scope *Scope) Fact(name string, value bool) {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	scope.facts[name] = value
}

// Native records an explicitly selected native diagnostic without report data.
func (scope *Scope) Native(err NativeError) {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	scope.nativeErrors = append(scope.nativeErrors, err)
}

// Defer registers cleanup before an operation can acquire a resource. Cleanup
// callbacks must be idempotent when acquisition can fail partway through.
func (scope *Scope) Defer(cleanup func(context.Context) error) {
	if cleanup == nil {
		return
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	scope.cleanup = append(scope.cleanup, cleanup)
}

type disposition struct {
	status Status
	reason string
}

func (err *disposition) Error() string { return err.reason }

// SkipReason marks an unrequested mode or unavailable prerequisite before an
// attempt, without claiming a pass.
func SkipReason(reason string) error { return &disposition{status: Skip, reason: reason} }

// InconclusiveReason marks missing evidence for a check that was attempted.
func InconclusiveReason(reason string) error {
	return &disposition{status: Inconclusive, reason: reason}
}

// Disposition returns an explicit SKIP or INCONCLUSIVE carried by an error.
// Harness error sanitizers can preserve this classification while removing
// device identifiers from native diagnostic messages.
func Disposition(err error) (Status, bool) {
	var result *disposition
	if errors.As(err, &result) {
		return result.status, true
	}
	return "", false
}

// Run executes scenarios sequentially and always attempts registered cleanup.
// A scenario error appears in its Result; malformed scenario definitions and
// cancellation of the overall run are also returned to the caller.
func Run(ctx context.Context, scenarios []Scenario, options Options) (Report, error) {
	started := time.Now()
	report := Report{SchemaVersion: 1, StartedAt: started.UTC(), Environment: Environment{OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version(), GoroutinesBefore: runtime.NumGoroutine()}, Results: make([]Result, 0, len(scenarios))}
	finish := func(err error) (Report, error) {
		report.Duration = time.Since(started)
		report.Environment.GoroutinesAfter = runtime.NumGoroutine()
		return report, err
	}
	if ctx == nil {
		return finish(errors.New("diagnostics: context is required"))
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 2 * time.Second
	}
	seen := make(map[string]bool)
	for _, scenario := range scenarios {
		if scenario.ID == "" || scenario.Run == nil || scenario.Timeout <= 0 || seen[scenario.ID] {
			return finish(errors.New("diagnostics: scenarios require unique IDs, positive timeouts and callbacks"))
		}
		switch scenario.Mode {
		case Deterministic, Hardware, Strict, Interactive:
		default:
			return finish(errors.New("diagnostics: unknown execution mode"))
		}
		seen[scenario.ID] = true
	}
	for _, scenario := range scenarios {
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		result := runScenario(ctx, scenario, options)
		report.Results = append(report.Results, result)
	}
	return finish(ctx.Err())
}

func runScenario(ctx context.Context, scenario Scenario, options Options) Result {
	started := time.Now()
	result := Result{ScenarioID: scenario.ID, Layer: scenario.Layer, Mode: scenario.Mode, Status: Pass, Requirements: append([]string(nil), scenario.Requirements...), StartedAt: started.UTC()}
	scope := &Scope{counters: make(map[string]uint64), facts: make(map[string]bool)}
	if scenario.Mode != Deterministic && !options.EnabledModes[scenario.Mode] {
		result.Status, result.Reason = Skip, "execution mode not requested: "+string(scenario.Mode)
		result.Cleanup.Complete = true
		result.Duration = time.Since(started)
		return result
	}
	for _, requirement := range scenario.Requirements {
		if !options.Capabilities[requirement] {
			result.Status, result.Reason = Skip, "unavailable requirement: "+requirement
			result.Cleanup.Complete = true
			result.Duration = time.Since(started)
			return result
		}
	}
	bounded, cancel := context.WithTimeout(ctx, scenario.Timeout)
	err := invoke(bounded, func(ctx context.Context) error { return scenario.Run(ctx, scope) })
	if err == nil {
		err = bounded.Err()
	}
	cancel()
	if err != nil {
		result.Status, result.Reason = Fail, err.Error()
		var status *disposition
		if errors.As(err, &status) {
			result.Status = status.status
		}
	}
	cleanupStarted := time.Now()
	// Cleanup gets an independent budget even after scenario/parent cancellation.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
	scope.mu.Lock()
	cleanup := append([]func(context.Context) error(nil), scope.cleanup...)
	scope.mu.Unlock()
	for i := len(cleanup) - 1; i >= 0; i-- {
		if err := invoke(cleanupCtx, cleanup[i]); err != nil {
			result.Cleanup.Errors = append(result.Cleanup.Errors, err.Error())
		}
	}
	if err := cleanupCtx.Err(); err != nil && len(result.Cleanup.Errors) == 0 {
		result.Cleanup.Errors = append(result.Cleanup.Errors, err.Error())
	}
	cleanupCancel()
	result.Cleanup.Duration = time.Since(cleanupStarted)
	result.Cleanup.Complete = len(result.Cleanup.Errors) == 0
	if !result.Cleanup.Complete {
		result.Status = Fail
		if result.Reason == "" {
			result.Reason = "cleanup failed"
		}
	}
	scope.mu.Lock()
	result.Counters = make(map[string]uint64, len(scope.counters))
	for name, value := range scope.counters {
		result.Counters[name] = value
	}
	result.Facts = make(map[string]bool, len(scope.facts))
	for name, value := range scope.facts {
		result.Facts[name] = value
	}
	result.NativeErrors = append([]NativeError(nil), scope.nativeErrors...)
	scope.mu.Unlock()
	if result.Status == Pass && scenario.Validate != nil {
		// A validator cannot rewrite the recorded observations or cleanup outcome.
		evidence := result
		evidence.Counters = maps.Clone(result.Counters)
		evidence.Facts = maps.Clone(result.Facts)
		evidence.Requirements = append([]string(nil), result.Requirements...)
		evidence.NativeErrors = append([]NativeError(nil), result.NativeErrors...)
		evidence.Cleanup.Errors = append([]string(nil), result.Cleanup.Errors...)
		if err := invoke(context.Background(), func(context.Context) error { return scenario.Validate(evidence) }); err != nil {
			result.Status, result.Reason = Fail, "evidence validation failed: "+err.Error()
		}
	}
	result.Duration = time.Since(started)
	return result
}

func invoke(ctx context.Context, callback func(context.Context) error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("diagnostics: callback panic (%T)", recovered)
		}
	}()
	return callback(ctx)
}

// WriteJSON emits one complete report suitable for CI artifacts. No environment
// variables or device metadata are collected automatically.
func WriteJSON(writer io.Writer, report Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
