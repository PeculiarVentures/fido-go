//go:build hid_diagnostics

package client_test

import (
	"testing"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func terraValidClientEvidence(d clientDiagnosticDefinition) diagnostics.Result {
	r := diagnostics.Result{ScenarioID: d.id, Layer: "client/ctap2", Mode: d.mode, Cleanup: diagnostics.Cleanup{Complete: true}, Facts: map[string]bool{}, Counters: map[string]uint64{"targets_selected": 1, "sdk_opened": d.minimumOpens, "sdk_closed": d.minimumOpens}}
	for _, f := range []string{"fresh_info_read", "exact_selector_required", "all_sdk_closed", "secrets_wiped", "final_pin_state_known"} {
		r.Facts[f] = true
	}
	for _, f := range d.facts {
		r.Facts[f] = true
	}
	r.Facts["physical_identity_proven"] = false
	r.Facts["harness_replayed_mutation"] = false
	for k, v := range d.counters {
		r.Counters[k] = v
	}
	if r.Facts["credential_enumerated"] {
		r.Counters["credential_readback_rows"] = 1
	}
	return r
}

func TestTerraClientEvidenceRejectsMissingAndContradictoryFacts(t *testing.T) {
	for _, d := range clientDiagnosticDefinitions() {
		t.Run(d.id, func(t *testing.T) {
			valid := terraValidClientEvidence(d)
			if err := validateClientDiagnosticEvidence(d, valid); err != nil {
				t.Fatalf("valid evidence: %v", err)
			}
			facts := append([]string{"fresh_info_read", "exact_selector_required", "all_sdk_closed", "secrets_wiped", "final_pin_state_known"}, d.facts...)
			for _, name := range facts {
				for _, remove := range []bool{true, false} {
					r := terraValidClientEvidence(d)
					if remove {
						delete(r.Facts, name)
					} else {
						r.Facts[name] = false
					}
					if validateClientDiagnosticEvidence(d, r) == nil {
						t.Errorf("accepted missing/false fact %s", name)
					}
				}
			}
			for _, name := range []string{"physical_identity_proven", "harness_replayed_mutation"} {
				for _, remove := range []bool{true, false} {
					r := terraValidClientEvidence(d)
					if remove {
						delete(r.Facts, name)
					} else {
						r.Facts[name] = true
					}
					if validateClientDiagnosticEvidence(d, r) == nil {
						t.Errorf("accepted absent/true %s", name)
					}
				}
			}
			for name := range d.counters {
				for _, remove := range []bool{true, false} {
					r := terraValidClientEvidence(d)
					if remove {
						delete(r.Counters, name)
					} else {
						r.Counters[name]++
					}
					if validateClientDiagnosticEvidence(d, r) == nil {
						t.Errorf("accepted missing/extra count %s", name)
					}
				}
			}
			if valid.Facts["credential_enumerated"] {
				r := terraValidClientEvidence(d)
				r.Counters["credential_readback_rows"] = 0
				if validateClientDiagnosticEvidence(d, r) == nil {
					t.Error("accepted empty credential readback")
				}
			}
			for _, mutate := range []func(*diagnostics.Result){func(r *diagnostics.Result) { r.Counters["sdk_closed"]++ }, func(r *diagnostics.Result) { r.Cleanup.Complete = false }, func(r *diagnostics.Result) { r.Cleanup.Errors = []string{"failure"} }, func(r *diagnostics.Result) { r.NativeErrors = []diagnostics.NativeError{{Domain: "test", Code: 1}} }} {
				r := terraValidClientEvidence(d)
				mutate(&r)
				if validateClientDiagnosticEvidence(d, r) == nil {
					t.Error("accepted inconsistent cleanup/session evidence")
				}
			}
		})
	}
}
