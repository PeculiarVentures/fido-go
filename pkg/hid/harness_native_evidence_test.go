//go:build hid_diagnostics

package hid

import "github.com/PeculiarVentures/fido-go/internal/diagnostics"

func nativeDiagnosticEvidence(facts ...string) func(diagnostics.Result) error {
	return func(r diagnostics.Result) error {
		var e diagnostics.Evidence

		for _, fact := range facts {
			if !r.Facts[fact] {
				e.Errorf("scenario %s missing evidence %s", r.ScenarioID, fact)
			}
		}
		if r.Facts["native_entry_confirmed"] {
			e.Errorf("synthetic scenario %s claims IOKit entry", r.ScenarioID)
		}
		if r.Counters[diagnosticWriterGeneration] == 0 {
			e.Errorf("scenario %s missing writer generation", r.ScenarioID)
		}
		if r.ScenarioID == "darwin.setup-mask-failure" {
			calls, recorded := r.Counters["set_report_calls"]
			if !recorded || calls != 0 {
				e.Errorf("setup fault lacks evidence of zero native submissions")
			}
		}
		return e.Err()
	}
}
