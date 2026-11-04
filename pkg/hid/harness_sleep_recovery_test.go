//go:build hid_diagnostics && integration

package hid

import (
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

// sleepRecoveryCandidates resolves unique descriptors only within the supplied
// complete observation. It rejects ambiguous candidates, never uses VID/PID
// alone, and does not prove physical identity.
func sleepRecoveryCandidates(expected, current []Endpoint) ([]Endpoint, error) {
	seen := make(map[EndpointID]bool, len(current))
	for _, endpoint := range current {
		if seen[endpoint.ID] {
			return nil, diagnostics.InconclusiveReason("sleep recovery inventory has duplicate endpoint addresses")
		}
		seen[endpoint.ID] = true
	}
	selected := make([]Endpoint, 0, len(expected))
	claimed := make(map[EndpointID]bool, len(expected))
	for _, target := range expected {
		var candidate Endpoint
		matches := 0
		for _, observed := range current {
			if sameRecoveryDescriptor(target, observed) {
				candidate = observed
				matches++
			}
		}
		if matches != 1 || claimed[candidate.ID] {
			return nil, diagnostics.InconclusiveReason("sleep recovery descriptor is absent or ambiguous in the complete inventory")
		}
		claimed[candidate.ID] = true
		selected = append(selected, candidate)
	}
	return selected, nil
}
