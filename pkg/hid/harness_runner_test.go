//go:build hid_diagnostics

package hid

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

type hidDiagnosticsOptions struct {
	Hardware          bool
	EndpointIDs       []EndpointID
	StrictIOKit       bool
	ScenarioIDs       []string
	InteractiveUnplug bool
	InteractiveSleep  bool
	OperatorPrompt    func(context.Context, diagnosticOperatorAction) error
}

type diagnosticOperatorAction struct {
	Phase      string
	KeyOrdinal int
	KeyCount   int
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
	callbacks := []diagnosticRun{lifecycleDiagnosticRun()}
	callbacks = append(callbacks, platformDiagnosticRuns(options)...)
	callbacks = append(callbacks, hardwareDiagnosticRuns(options)...)
	callbacks = append(callbacks, portableHardwareDiagnosticRuns(options)...)
	callbacks = append(callbacks, supplementalHardwareDiagnosticRuns(options)...)
	callbacks = append(callbacks, sleepHardwareDiagnosticRuns(options)...)
	capabilities := hidDiagnosticCapabilities()
	scenarios, err := bindDiagnosticRuns(hidDiagnosticDefinitions(), callbacks, capabilities)
	if err != nil {
		return diagnostics.Report{}, err
	}
	scenarios, err = diagnostics.Select(scenarios, options.ScenarioIDs)
	if err != nil {
		return diagnostics.Report{}, err
	}
	for index := range scenarios {
		if scenarios[index].Mode != diagnostics.Deterministic {
			validate := scenarios[index].Validate
			scenarios[index].Validate = func(result diagnostics.Result) error {
				if len(options.EndpointIDs) > 0 && result.Counters[diagnosticKeysSelected] != uint64(len(options.EndpointIDs)) {
					return errors.New("selected endpoint count does not match evidence")
				}
				return validate(result)
			}
		}
		run := scenarios[index].Run
		id := scenarios[index].ID
		scenarios[index].Run = func(ctx context.Context, scope *diagnostics.Scope) error {
			if !diagnosticInteractiveRequested(id, options) {
				return diagnostics.SkipReason("this interactive HID scenario was not requested")
			}
			return diagnosticSafeError(scope, run(ctx, scope))
		}
	}
	return diagnostics.Run(ctx, scenarios, diagnostics.Options{CleanupTimeout: 3 * time.Second, Capabilities: capabilities, EnabledModes: map[diagnostics.Mode]bool{
		diagnostics.Hardware:    options.Hardware,
		diagnostics.Strict:      options.Hardware && options.StrictIOKit,
		diagnostics.Interactive: options.Hardware && (options.InteractiveUnplug || options.InteractiveSleep),
	}})
}

func hidDiagnosticCapabilities() map[string]bool {
	capabilities := map[string]bool{"go-lifecycle": true, "native-hid": runtime.GOOS == "linux" || runtime.GOOS == "windows" || platformDiagnosticCapabilities()["darwin-cgo"]}
	for name, available := range platformDiagnosticCapabilities() {
		capabilities[name] = available
	}
	for name, available := range hardwareDiagnosticCapabilities() {
		capabilities[name] = available
	}
	for name, available := range sleepDiagnosticCapabilities() {
		capabilities[name] = available
	}
	return capabilities
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

// Distinct manual actions share the runner's Interactive mode, but never share
// authorization. Opting into sleep cannot trigger unplug prompts or vice versa.
func diagnosticInteractiveRequested(id string, options hidDiagnosticsOptions) bool {
	switch id {
	case "hardware.unplug-replug":
		return options.InteractiveUnplug
	case "hardware.sleep-wake-idle", "hardware.sleep-wake-exchange":
		return options.InteractiveSleep
	default:
		return true
	}
}
