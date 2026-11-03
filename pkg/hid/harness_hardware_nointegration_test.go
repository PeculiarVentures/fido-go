//go:build hid_diagnostics && !integration

package hid

import "github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"

func hardwareDiagnosticCapabilities() map[string]bool {
	return map[string]bool{"integration-build": false}
}
func hardwareDiagnosticScenarios(options hidDiagnosticsOptions) []diagnostics.Scenario {
	return unavailableHardwareScenarios(options, []string{"hardware.sigurg-ping", "hardware.strict-iokit-entry"}, "hardware diagnostics require integration build tag")
}
func portableHardwareDiagnosticScenarios(options hidDiagnosticsOptions) []diagnostics.Scenario {
	return unavailableHardwareScenarios(options, []string{"hardware.multiframe-ping", "hardware.parallel-exchange"}, "hardware diagnostics require integration build tag")
}
func supplementalHardwareDiagnosticScenarios(options hidDiagnosticsOptions) []diagnostics.Scenario {
	return unavailableHardwareScenarios(options, []string{"hardware.cancel-close", "hardware.unplug-replug"}, "hardware diagnostics require integration build tag")
}
