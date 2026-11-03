//go:build hid_diagnostics && integration && (!darwin || !cgo)

package hid

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

func hardwareDiagnosticScenarios(options hidDiagnosticsOptions) []diagnostics.Scenario {
	return unavailableHardwareScenarios(options, []string{"hardware.sigurg-ping", "hardware.strict-iokit-entry"}, "Darwin cgo signal probes unavailable")
}

func hardwareDiagnosticCapabilities() map[string]bool {
	return map[string]bool{"integration-build": true}
}
