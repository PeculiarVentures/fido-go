package diagnostics_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
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

func TestRunnerValidatesCleanupEvidenceBeforePersistingVerdict(t *testing.T) {
	for _, complete := range []bool{false, true} {
		scenario := diagnostics.Scenario{ID: "validated", Layer: "test", Timeout: time.Second,
			Run: func(_ context.Context, scope *diagnostics.Scope) error {
				scope.Defer(func(context.Context) error { scope.Fact("joined", complete); return nil })
				return nil
			},
			Validate: func(r diagnostics.Result) error {
				if !r.Cleanup.Complete {
					t.Error("validation ran before cleanup")
				}
				var e diagnostics.Evidence
				e.RequireFacts(r, "joined")
				return e.Err()
			},
		}
		report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "report.json")
		if err := diagnostics.WriteFile(path, report); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var stored diagnostics.Report
		if err := json.Unmarshal(data, &stored); err != nil {
			t.Fatal(err)
		}
		want := diagnostics.Fail
		if complete {
			want = diagnostics.Pass
		}
		r := stored.Results[0]
		if r.Status != want || r.Layer != "test" || !r.Cleanup.Complete || (!complete && r.Reason == "") {
			t.Fatalf("persisted verdict=%+v want=%s", r, want)
		}
	}
}

func TestRunnerDoesNotValidateUnqualifiedAttempts(t *testing.T) {
	for _, tc := range []struct {
		name               string
		mode               diagnostics.Mode
		requirement        string
		runErr, cleanupErr error
		want               diagnostics.Status
	}{
		{name: "opt-out", mode: diagnostics.Hardware, want: diagnostics.Skip},
		{name: "prerequisite", requirement: "unavailable", want: diagnostics.Skip},
		{name: "inconclusive", runErr: diagnostics.InconclusiveReason("no evidence"), want: diagnostics.Inconclusive},
		{name: "failed", runErr: errors.New("operation failed"), want: diagnostics.Fail},
		{name: "cleanup", cleanupErr: errors.New("cleanup failed"), want: diagnostics.Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validated := false
			s := diagnostics.Scenario{ID: tc.name, Mode: tc.mode, Timeout: time.Second,
				Run: func(_ context.Context, scope *diagnostics.Scope) error {
					scope.Defer(func(context.Context) error { return tc.cleanupErr })
					return tc.runErr
				}, Validate: func(diagnostics.Result) error { validated = true; return nil },
			}
			if tc.requirement != "" {
				s.Requirements = []string{tc.requirement}
			}
			r, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{s}, diagnostics.Options{})
			if err != nil || validated || r.Results[0].Status != tc.want {
				t.Fatalf("report=%+v err=%v validated=%v", r, err, validated)
			}
		})
	}
}

func TestRunnerValidatorPanicFailsWithoutLeakingPayload(t *testing.T) {
	s := diagnostics.Scenario{ID: "panic", Timeout: time.Second,
		Run:      func(context.Context, *diagnostics.Scope) error { return nil },
		Validate: func(diagnostics.Result) error { panic("private marker") },
	}
	r, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{s}, diagnostics.Options{})
	if err != nil || r.Results[0].Status != diagnostics.Fail || bytes.Contains([]byte(r.Results[0].Reason), []byte("private marker")) {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}

func TestRunnerValidatorCannotRewriteObservedEvidence(t *testing.T) {
	s := diagnostics.Scenario{ID: "immutable", Timeout: time.Second,
		Run: func(_ context.Context, scope *diagnostics.Scope) error {
			scope.Fact("observed", false)
			scope.Counter("submissions", 1)
			return nil
		},
		Validate: func(r diagnostics.Result) error {
			r.Facts["observed"] = true
			r.Counters["submissions"] = 2
			return nil
		},
	}
	r, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{s}, diagnostics.Options{})
	if err != nil || r.Results[0].Facts["observed"] || r.Results[0].Counters["submissions"] != 1 {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}
