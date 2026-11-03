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
	Hardware          bool
	EndpointIDs       []EndpointID
	StrictIOKit       bool
	ScenarioIDs       []string
	InteractiveUnplug bool
	OperatorPrompt    func(context.Context, diagnosticOperatorAction) error
}

type diagnosticOperatorAction struct {
	Phase      string
	KeyOrdinal int
	VendorID   uint16
	ProductID  uint16
}

// runHIDDiagnostics is the test-only bridge used by independent entrypoints.
// Endpoint selectors never appear in report records.
func runHIDDiagnostics(ctx context.Context, options hidDiagnosticsOptions) (diagnostics.Report, error) {
	options.EndpointIDs = append([]EndpointID(nil), options.EndpointIDs...)
	options.ScenarioIDs = append([]string(nil), options.ScenarioIDs...)
	if options.Hardware && os.Getenv("FIDO_HID_DIAGNOSTICS") != "1" {
		return diagnostics.Report{}, errors.New("HID hardware diagnostics require FIDO_HID_DIAGNOSTICS=1")
	}
	scenarios := []diagnostics.Scenario{lifecycleDiagnosticScenario()}
	scenarios = append(scenarios, platformDiagnosticScenarios(options)...)
	scenarios = append(scenarios, hardwareDiagnosticScenarios(options)...)
	scenarios = append(scenarios, portableHardwareDiagnosticScenarios(options)...)
	scenarios = append(scenarios, supplementalHardwareDiagnosticScenarios(options)...)
	var err error
	scenarios, err = selectDiagnosticScenarios(scenarios, options.ScenarioIDs)
	if err != nil {
		return diagnostics.Report{}, err
	}
	for index := range scenarios {
		run := scenarios[index].Run
		scenarios[index].Run = func(ctx context.Context, scope *diagnostics.Scope) error {
			return diagnosticSafeError(scope, run(ctx, scope))
		}
	}
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

// Select before running any scenario: unknown IDs must never start hardware I/O.
func selectDiagnosticScenarios(scenarios []diagnostics.Scenario, ids []string) ([]diagnostics.Scenario, error) {
	if len(ids) == 0 {
		return scenarios, nil
	}
	known := make(map[string]diagnostics.Scenario, len(scenarios))
	for _, scenario := range scenarios {
		known[scenario.ID] = scenario
	}
	selected := make([]diagnostics.Scenario, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		scenario, ok := known[id]
		if !ok {
			return nil, errors.New("unknown HID diagnostic scenario ID")
		}
		if seen[id] {
			return nil, errors.New("duplicate HID diagnostic scenario ID")
		}
		seen[id] = true
		selected = append(selected, scenario)
	}
	return selected, nil
}
