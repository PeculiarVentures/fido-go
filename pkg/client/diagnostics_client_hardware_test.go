//go:build hid_diagnostics && integration

package client_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/client"
)

func TestClientDiagnosticsHardware(t *testing.T) {
	if os.Getenv("FIDO_CLIENT_DIAGNOSTICS") != "1" {
		t.Skip("set FIDO_CLIENT_DIAGNOSTICS=1 for explicitly selected client hardware diagnostics")
	}
	options := clientDiagnosticOptions{
		Endpoint:    os.Getenv("FIDO_CLIENT_DIAGNOSTICS_ENDPOINT"),
		Hardware:    true,
		Credentials: os.Getenv("FIDO_CLIENT_DIAGNOSTICS_CREDENTIALS") == "1",
		Persistence: os.Getenv("FIDO_CLIENT_DIAGNOSTICS_PERSISTENCE") == "1",
		PINSet:      os.Getenv("FIDO_CLIENT_DIAGNOSTICS_PIN_SET") == "1",
		PINChange:   os.Getenv("FIDO_CLIENT_DIAGNOSTICS_PIN_CHANGE") == "1",
		Reset:       os.Getenv("FIDO_CLIENT_DIAGNOSTICS_RESET") == "1",
		PINFile:     os.Getenv("FIDO_CLIENT_DIAGNOSTICS_PIN_FILE"),
		NewPINFile:  os.Getenv("FIDO_CLIENT_DIAGNOSTICS_NEW_PIN_FILE"),
		TempPINFile: os.Getenv("FIDO_CLIENT_DIAGNOSTICS_TEMP_PIN_FILE"),
		Output:      os.Stdout,
	}
	if path := os.Getenv("FIDO_CLIENT_DIAGNOSTICS_ACK_FILE"); path != "" {
		options.Operator = clientDiagnosticFileOperator(path, os.Stdout)
	}
	ids, err := diagnostics.ParseScenarioIDs(os.Getenv("FIDO_CLIENT_DIAGNOSTICS_SCENARIOS"))
	if err != nil {
		t.Fatal(err)
	}
	// The implicit selection is read-only even if unrelated modifying opt-ins
	// remain in the caller's environment. Mutations always need an exact ID.
	if len(ids) == 0 {
		ids = []string{"client.info-pin-status"}
	}
	all, err := clientDiagnosticScenarios(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := diagnostics.Select(all, ids); err != nil {
		t.Fatal(err)
	}
	locator, err := client.NewDefaultLocator()
	if err != nil {
		t.Fatal("client diagnostic USB locator construction failed")
	}
	options.Locator = locator
	// Rebuild callbacks with the production locator only after all selectors
	// have been resolved; constructing this locator does not discover devices.
	all, err = clientDiagnosticScenarios(options)
	if err != nil {
		t.Fatal(err)
	}
	scenarios, err := diagnostics.Select(all, ids)
	if err != nil {
		t.Fatal(err)
	}
	budget := 2 * time.Minute
	for _, scenario := range scenarios {
		budget += scenario.Timeout + 2*time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	report, runErr := diagnostics.Run(ctx, scenarios, diagnostics.Options{
		CleanupTimeout: 2 * time.Minute,
		Capabilities:   clientDiagnosticCapabilities(options),
		EnabledModes: map[diagnostics.Mode]bool{
			diagnostics.Hardware:    true,
			diagnostics.Interactive: options.Persistence || options.Reset,
		},
	})
	if err := diagnostics.WriteFile(os.Getenv("FIDO_CLIENT_DIAGNOSTICS_REPORT"), report); err != nil {
		t.Fatal("client diagnostic report could not be written")
	}
	if runErr != nil {
		t.Fatal("client diagnostic run did not complete")
	}
	passes := 0
	for _, result := range report.Results {
		if result.Status == diagnostics.Skip {
			t.Logf("scenario %s skipped: %s", result.ScenarioID, result.Reason)
			continue
		}
		if result.Status != diagnostics.Pass {
			t.Errorf("scenario %s status=%s reason=%s", result.ScenarioID, result.Status, result.Reason)
			continue
		}
		passes++
		t.Logf("scenario %s status=PASS", result.ScenarioID)
	}
	if passes == 0 && !t.Failed() {
		t.Skip("selected client diagnostic prerequisites are unavailable; see report")
	}
}
