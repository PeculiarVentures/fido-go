//go:build hid_diagnostics

package hid

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func TestHIDDiagnostics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := runHIDDiagnostics(ctx, hidDiagnosticsOptions{})
	if reportErr := diagnostics.WriteFile(os.Getenv("FIDO_HID_DIAGNOSTICS_REPORT"), report); reportErr != nil {
		t.Fatal(reportErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	assertDiagnosticResults(t, report)
}

// Entrypoints translate the runner's finalized verdicts into test outcomes.
func assertDiagnosticResults(t *testing.T, report diagnostics.Report) {
	t.Helper()
	qualified := false
	for _, result := range report.Results {
		switch result.Status {
		case diagnostics.Pass:
			qualified = true
		case diagnostics.Fail:
			t.Errorf("scenario %s failed: %s", result.ScenarioID, result.Reason)
		case diagnostics.Skip:
			t.Logf("scenario %s skipped: %s", result.ScenarioID, result.Reason)
		case diagnostics.Inconclusive:
			if result.Mode == diagnostics.Strict {
				t.Logf("strict entry evidence unavailable: %s", result.Reason)
			} else {
				t.Errorf("scenario %s inconclusive: %s", result.ScenarioID, result.Reason)
			}
		}
	}
	if !t.Failed() && !qualified {
		t.Skip("requested diagnostics could not qualify; see scenario results")
	}
}
