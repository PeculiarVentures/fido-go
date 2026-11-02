package diagnostics_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

func TestRunnerRecordsOutcomesEvidenceAndRequirements(t *testing.T) {
	called := false
	scenarios := []diagnostics.Scenario{
		{ID: "pass", Timeout: time.Second, Run: func(_ context.Context, s *diagnostics.Scope) error {
			s.Counter("submissions", 1)
			s.Fact("mask_restored", true)
			s.Native(diagnostics.NativeError{Operation: "write", Domain: "pthread", Code: 7})
			return nil
		}},
		{ID: "unavailable", Requirements: []string{"hardware"}, Timeout: time.Second, Run: func(context.Context, *diagnostics.Scope) error { called = true; return nil }},
		{ID: "inconclusive", Timeout: time.Second, Run: func(context.Context, *diagnostics.Scope) error {
			return diagnostics.InconclusiveReason("entry not confirmed")
		}},
		{ID: "failed", Timeout: time.Second, Run: func(context.Context, *diagnostics.Scope) error { return errors.New("test failure") }},
	}
	report, err := diagnostics.Run(context.Background(), scenarios, diagnostics.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if called || len(report.Results) != 4 {
		t.Fatalf("called=%v results=%+v", called, report.Results)
	}
	want := []diagnostics.Status{diagnostics.Pass, diagnostics.Skip, diagnostics.Inconclusive, diagnostics.Fail}
	for i, r := range report.Results {
		if r.Status != want[i] || !r.Cleanup.Complete {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	if report.Results[0].Counters["submissions"] != 1 || !report.Results[0].Facts["mask_restored"] || len(report.Results[0].NativeErrors) != 1 || report.Results[0].NativeErrors[0].Code != 7 {
		t.Fatalf("evidence: %+v", report.Results[0])
	}
	var b bytes.Buffer
	if err := diagnostics.WriteJSON(&b, report); err != nil {
		t.Fatal(err)
	}
	var decoded diagnostics.Report
	if err := json.Unmarshal(b.Bytes(), &decoded); err != nil || decoded.SchemaVersion != 1 || decoded.Environment.OS == "" || len(decoded.Results) != 4 {
		t.Fatalf("JSON report: %+v %v", decoded, err)
	}
}
func TestRunnerCleanupAlwaysAttemptsLIFOAfterPanicAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var order []int
	independent := false
	scenario := diagnostics.Scenario{ID: "panic", Timeout: time.Second, Run: func(_ context.Context, s *diagnostics.Scope) error {
		s.Defer(func(c context.Context) error { order = append(order, 1); independent = c.Err() == nil; return nil })
		s.Defer(func(context.Context) error { order = append(order, 2); return errors.New("cleanup failure") })
		s.Defer(func(context.Context) error { order = append(order, 3); panic("secret") })
		cancel()
		panic("secret")
	}}
	report, err := diagnostics.Run(ctx, []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run error: %v", err)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Fail || r.Cleanup.Complete || len(r.Cleanup.Errors) != 2 || !independent || !reflect.DeepEqual(order, []int{3, 2, 1}) {
		t.Fatalf("cleanup: %+v order=%v independent=%v", r, order, independent)
	}
	if bytes.Contains([]byte(r.Reason), []byte("secret")) || bytes.Contains([]byte(r.Cleanup.Errors[0]), []byte("secret")) {
		t.Fatal("panic payload exposed")
	}
}
func TestRunnerRejectsInvalidDefinitionsBeforeExecution(t *testing.T) {
	called := false
	scenario := diagnostics.Scenario{ID: "duplicate", Timeout: time.Second, Run: func(context.Context, *diagnostics.Scope) error { called = true; return nil }}
	_, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario, scenario}, diagnostics.Options{})
	if err == nil || called {
		t.Fatalf("error=%v called=%v", err, called)
	}
}

func TestRunnerScenarioTimeoutStillRunsCleanup(t *testing.T) {
	cleaned := false
	r, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "timeout", Timeout: time.Millisecond, Run: func(ctx context.Context, s *diagnostics.Scope) error {
		s.Defer(func(ctx context.Context) error { cleaned = ctx.Err() == nil; return nil })
		<-ctx.Done()
		return ctx.Err()
	}}}, diagnostics.Options{})
	if err != nil || len(r.Results) != 1 || r.Results[0].Status != diagnostics.Fail || !cleaned || !r.Results[0].Cleanup.Complete {
		t.Fatalf("report=%+v err=%v cleaned=%v", r, err, cleaned)
	}
}
