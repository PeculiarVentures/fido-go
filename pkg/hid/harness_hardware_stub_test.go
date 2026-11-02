//go:build hid_diagnostics && (!integration || !darwin || !cgo)

package hid

import (
	"context"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"time"
)

func hardwareDiagnosticScenarios(options hidDiagnosticsOptions) []diagnostics.Scenario {
	return []diagnostics.Scenario{{ID: "hardware.sigurg-ping", Timeout: time.Second, Run: func(context.Context, *diagnostics.Scope) error {
		if options.Hardware {
			return diagnostics.InconclusiveReason("hardware diagnostics require integration tag and Darwin cgo")
		}
		return diagnostics.SkipReason("hardware diagnostics not requested")
	}}}
}

func hardwareDiagnosticCapabilities() map[string]bool {
	return map[string]bool{"integration-build": false}
}
