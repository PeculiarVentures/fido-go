//go:build hid_diagnostics && (!darwin || !cgo)

package hid

import (
	"context"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

func platformDiagnosticScenarios(hidDiagnosticsOptions) []diagnostics.Scenario {
	return []diagnostics.Scenario{{ID: "darwin.native-probes", Timeout: 1, Run: func(context.Context, *diagnostics.Scope) error {
		return diagnostics.SkipReason("Darwin cgo native probes unavailable")
	}}}
}

func platformDiagnosticCapabilities() map[string]bool { return map[string]bool{"darwin-cgo": false} }
