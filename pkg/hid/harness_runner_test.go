//go:build hid_diagnostics

package hid

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

type hidDiagnosticsOptions struct {
	Hardware    bool
	EndpointIDs []EndpointID
	StrictIOKit bool
}

// runHIDDiagnostics is the test-only bridge used by independent entrypoints.
// Endpoint selectors never appear in report records.
func runHIDDiagnostics(ctx context.Context, options hidDiagnosticsOptions) (diagnostics.Report, error) {
	if options.Hardware && os.Getenv("FIDO_HID_DIAGNOSTICS") != "1" {
		return diagnostics.Report{}, errors.New("HID hardware diagnostics require FIDO_HID_DIAGNOSTICS=1")
	}
	scenarios := []diagnostics.Scenario{lifecycleDiagnosticScenario()}
	scenarios = append(scenarios, platformDiagnosticScenarios(options)...)
	scenarios = append(scenarios, hardwareDiagnosticScenarios(options)...)
	capabilities := map[string]bool{"go-lifecycle": true}
	for name, available := range platformDiagnosticCapabilities() {
		capabilities[name] = available
	}
	for name, available := range hardwareDiagnosticCapabilities() {
		capabilities[name] = available
	}
	return diagnostics.Run(ctx, scenarios, diagnostics.Options{CleanupTimeout: 3 * time.Second, Capabilities: capabilities})
}

// withDiagnosticDevice protects the native device's lifetime during attachment.
// The callback must be bounded and must not reenter this connection's methods.
// Retirement holds this same mutex when revoking admission, so no native close
// can begin during the callback, and an already-retiring device is never read.
func withDiagnosticDevice(conn Conn, attach func(driver.Device) error) error {
	raw, ok := conn.(*connection)
	if !ok || raw == nil || attach == nil {
		return ErrInvalidArgument
	}
	raw.mu.Lock()
	defer raw.mu.Unlock()
	if raw.retiring {
		return ErrClosed
	}
	return attach(raw.device)
}
