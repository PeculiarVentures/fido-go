//go:build hid_diagnostics && (!integration || !darwin || !cgo)

package hid

import (
	"context"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"testing"
)

func TestDiagnosticsHardwareUnavailableIsInconclusive(t *testing.T) {
	report, err := diagnostics.Run(context.Background(), hardwareDiagnosticScenarios(hidDiagnosticsOptions{Hardware: true}), diagnostics.Options{})
	if err != nil || len(report.Results) != 1 || report.Results[0].Status != diagnostics.Inconclusive {
		t.Fatalf("hardware unavailable: %+v %v", report, err)
	}
}
