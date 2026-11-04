//go:build hid_diagnostics && integration

package usb_test

import (
	"context"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

func TestUSBDiagnosticsHardware(t *testing.T) {
	if os.Getenv("FIDO_USB_DIAGNOSTICS") != "1" {
		t.Skip("set FIDO_USB_DIAGNOSTICS=1 for read-only USB session diagnostics")
	}
	ids, err := diagnostics.ParseScenarioIDs(os.Getenv("FIDO_USB_DIAGNOSTICS_SCENARIOS"))
	if err != nil {
		t.Fatal(err)
	}
	var endpoints []string
	if value := os.Getenv("FIDO_USB_DIAGNOSTICS_ENDPOINTS"); value != "" {
		endpoints = strings.Split(value, ",")
	}
	sleep := os.Getenv("FIDO_USB_DIAGNOSTICS_SLEEP") == "1"
	options := usbSleepDiagnosticOptions{Hardware: true, InteractiveSleep: sleep}
	if sleep {
		options.OperatorPrompt = func(ctx context.Context, phase string, keys int) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return writeUSBOperatorAction(os.Stdout, phase, keys)
		}
	}
	all := usbDiagnosticScenarios(usb.NewHIDBackend(), endpoints)
	all = append(all, usbSleepDiagnosticScenarios(hid.New(), endpoints, options)...)
	scenarios, err := diagnostics.Select(all, ids)
	if err != nil {
		t.Fatal(err)
	}
	duration := 2 * time.Minute
	if sleep {
		duration = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	report, err := diagnostics.Run(ctx, scenarios, diagnostics.Options{CleanupTimeout: 3 * time.Second, Capabilities: usbDiagnosticCapabilities(), EnabledModes: map[diagnostics.Mode]bool{diagnostics.Hardware: true, diagnostics.Interactive: sleep}})
	if writeErr := diagnostics.WriteFile(os.Getenv("FIDO_USB_DIAGNOSTICS_REPORT"), report); writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	qualified := false
	for _, result := range report.Results {
		if result.Status == diagnostics.Skip {
			t.Logf("scenario %s skipped: %s", result.ScenarioID, result.Reason)
			continue
		}
		if result.Status != diagnostics.Pass {
			t.Errorf("scenario %s status=%s reason=%s", result.ScenarioID, result.Status, result.Reason)
		} else {
			qualified = true
		}
	}
	if !t.Failed() && !qualified {
		t.Skip("requested USB diagnostics are unavailable; see scenario results")
	}
}
