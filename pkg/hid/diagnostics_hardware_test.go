//go:build hid_diagnostics && integration

package hid

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func TestHIDDiagnosticsHardware(t *testing.T) {
	if os.Getenv("FIDO_HID_DIAGNOSTICS") != "1" {
		t.Skip("set FIDO_HID_DIAGNOSTICS=1 for read-only hardware diagnostics")
	}
	unplug, sleep, identical := diagnosticInteractiveModes(os.Getenv)
	opts := hidDiagnosticsOptions{Hardware: true, StrictIOKit: os.Getenv("FIDO_HID_DIAGNOSTICS_STRICT") == "1", InteractiveUnplug: unplug, InteractiveSleep: sleep, InteractiveIdentical: identical}
	var selectErr error
	opts.ScenarioIDs, selectErr = diagnostics.ParseScenarioIDs(os.Getenv("FIDO_HID_DIAGNOSTICS_SCENARIOS"))
	if selectErr != nil {
		t.Fatal(selectErr)
	}
	if opts.InteractiveUnplug || opts.InteractiveSleep || opts.InteractiveIdentical {
		opts.OperatorPrompt = func(ctx context.Context, action diagnosticOperatorAction) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return writeDiagnosticOperatorAction(os.Stdout, action)
		}
	}
	if ids := os.Getenv("FIDO_HID_DIAGNOSTICS_ENDPOINTS"); ids != "" {
		for _, id := range strings.Split(ids, ",") {
			if id == "" {
				t.Fatal("empty endpoint selector")
			}
			opts.EndpointIDs = append(opts.EndpointIDs, EndpointID(id))
		}
	}
	duration := 2 * time.Minute
	if opts.InteractiveUnplug || opts.InteractiveSleep {
		duration = 30 * time.Minute
	}
	if opts.InteractiveIdentical {
		duration = 60 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	report, err := runHIDDiagnostics(ctx, opts)
	if reportErr := diagnostics.WriteFile(os.Getenv("FIDO_HID_DIAGNOSTICS_REPORT"), report); reportErr != nil {
		t.Fatal(reportErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	assertDiagnosticResults(t, report)
}

func diagnosticInteractiveModes(getenv func(string) string) (bool, bool, bool) {
	return getenv("FIDO_HID_DIAGNOSTICS_UNPLUG") == "1", getenv("FIDO_HID_DIAGNOSTICS_SLEEP") == "1", getenv("FIDO_HID_DIAGNOSTICS_IDENTICAL") == "1"
}
