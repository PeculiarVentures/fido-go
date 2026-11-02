//go:build hid_diagnostics

package hid

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

func TestDiagnosticsLifecycleScenarioEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := diagnostics.Run(ctx, []diagnostics.Scenario{lifecycleDiagnosticScenario()}, diagnostics.Options{Capabilities: map[string]bool{"go-lifecycle": true}})
	if err != nil || len(report.Results) != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Pass || !r.Cleanup.Complete || r.Counters["old_device_close_count"] != 1 {
		t.Fatalf("lifecycle=%+v", r)
	}
	for _, fact := range []string{"read_entered", "write_entered", "cancellation_returned_before_completion", "close_wait_bounded", "cleanup_deferred_until_completion", "retiring_endpoint_excluded", "repeated_close_shared_cleanup", "late_input_isolated", "fresh_connection_usable"} {
		if !r.Facts[fact] {
			t.Errorf("missing lifecycle evidence %q", fact)
		}
	}
}

func TestHIDDiagnostics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := runHIDDiagnostics(ctx, hidDiagnosticsOptions{})
	if reportErr := writeDiagnosticReport(os.Getenv("FIDO_HID_DIAGNOSTICS_REPORT"), report); reportErr != nil {
		t.Fatal(reportErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnosticScenarios(t, report, expectedDeterministicDiagnosticIDs())
	assertNativeDiagnosticEvidence(t, report)
}
func requireDiagnosticScenarios(t *testing.T, report diagnostics.Report, ids []string) {
	t.Helper()
	results := make(map[string]diagnostics.Result, len(report.Results))
	for _, r := range report.Results {
		if _, ok := results[r.ScenarioID]; ok {
			t.Errorf("duplicate scenario %q", r.ScenarioID)
		}
		results[r.ScenarioID] = r
		if r.Status == diagnostics.Fail {
			t.Errorf("scenario %s failed: %s; cleanup=%+v", r.ScenarioID, r.Reason, r.Cleanup)
		}
	}
	for _, id := range ids {
		r, ok := results[id]
		if !ok {
			t.Errorf("required scenario %q absent", id)
			continue
		}
		if r.Status != diagnostics.Pass || !r.Cleanup.Complete {
			t.Errorf("required scenario %q status=%s cleanup=%+v reason=%s", id, r.Status, r.Cleanup, r.Reason)
		}
	}
}

// writeDiagnosticReport is shared by the software and hardware entrypoints.
func writeDiagnosticReport(path string, report diagnostics.Report) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return errors.New("diagnostic report path must be absolute")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open diagnostic report: %w", err)
	}
	if err = f.Chmod(0600); err != nil {
		return errors.Join(fmt.Errorf("restrict diagnostic report permissions: %w", err), f.Close())
	}
	writeErr := diagnostics.WriteJSON(f, report)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}
