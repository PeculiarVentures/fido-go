//go:build hid_diagnostics

package hid

import (
	"context"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"time"
)

func unavailableHardwareScenarios(options hidDiagnosticsOptions, ids []string, reason string) []diagnostics.Scenario {
	scenarios := make([]diagnostics.Scenario, 0, len(ids))
	for _, id := range ids {
		scenarios = append(scenarios, diagnostics.Scenario{ID: id, Timeout: time.Second, Run: func(context.Context, *diagnostics.Scope) error {
			if !options.Hardware {
				return diagnostics.SkipReason("hardware diagnostics not requested")
			}
			if id == "hardware.unplug-replug" && !options.InteractiveUnplug {
				return diagnostics.SkipReason("interactive unplug diagnostic not requested")
			}
			if id == "hardware.strict-iokit-entry" && !options.StrictIOKit {
				return diagnostics.SkipReason("strict IOKit-entry diagnostic not requested")
			}
			return diagnostics.InconclusiveReason(reason)
		}})
	}
	return scenarios
}
