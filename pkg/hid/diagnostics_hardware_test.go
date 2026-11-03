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
	opts := hidDiagnosticsOptions{Hardware: true, StrictIOKit: os.Getenv("FIDO_HID_DIAGNOSTICS_STRICT") == "1", InteractiveUnplug: os.Getenv("FIDO_HID_DIAGNOSTICS_UNPLUG") == "1"}
	var selectErr error
	opts.ScenarioIDs, selectErr = diagnostics.ParseScenarioIDs(os.Getenv("FIDO_HID_DIAGNOSTICS_SCENARIOS"))
	if selectErr != nil {
		t.Fatal(selectErr)
	}
	if opts.InteractiveUnplug {
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
	if opts.InteractiveUnplug {
		duration = 30 * time.Minute
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
