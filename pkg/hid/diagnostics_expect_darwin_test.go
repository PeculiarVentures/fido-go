//go:build hid_diagnostics && darwin && cgo

package hid

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"testing"
)

func expectedDeterministicDiagnosticIDs() []string {
	return []string{"lifecycle.blocked-read-write", "darwin.mask-unblocked", "darwin.mask-blocked", "darwin.synthetic-sigurg", "darwin.setup-mask-failure", "darwin.restore-mask-failure", "darwin.native-and-restore-failure", "darwin.blocked-native-retirement"}
}

func assertNativeDiagnosticEvidence(t *testing.T, report diagnostics.Report) {
	t.Helper()
	required := map[string][]string{
		"darwin.mask-unblocked":             {"synthetic_call", "mask_restored", "critical_sigurg_blocked", "before_unrelated_blocked", "after_unrelated_blocked", "native_submission_succeeded", "writer_joined", "device_closed"},
		"darwin.mask-blocked":               {"synthetic_call", "mask_restored", "before_sigurg_blocked", "after_sigurg_blocked", "native_submission_succeeded", "writer_joined", "device_closed"},
		"darwin.synthetic-sigurg":           {"synthetic_call", "mask_restored", "pending_inside_synthetic_call", "pending_sigurg", "kill_succeeded", "kill_target_generation_matches", "writer_joined", "device_closed"},
		"darwin.setup-mask-failure":         {"setup_failed_not_submitted", "original_mask_intact", "old_connection_rejected", "no_generation_reuse", "fresh_connection_usable", "writer_exited", "writer_joined"},
		"darwin.restore-mask-failure":       {"completed_outcome_preserved", "protected_mask_retained_after_restore_failure", "old_connection_rejected", "no_generation_reuse", "fresh_connection_usable", "writer_exited", "writer_joined"},
		"darwin.native-and-restore-failure": {"native_and_restore_errors_preserved", "protected_mask_retained_after_restore_failure", "old_connection_rejected", "no_generation_reuse", "fresh_connection_usable", "writer_exited", "writer_joined"},
		"darwin.blocked-native-retirement":  {"native_barrier_entered", "cleanup_deferred_until_native_completion", "canceled_wait_preserved_late_native_completion", "writer_joined", "device_closed"},
	}
	for _, r := range report.Results {
		facts, ok := required[r.ScenarioID]
		if !ok {
			continue
		}
		for _, fact := range facts {
			if !r.Facts[fact] {
				t.Errorf("scenario %s missing evidence %s", r.ScenarioID, fact)
			}
		}
		if r.Facts["native_entry_confirmed"] {
			t.Errorf("synthetic scenario %s claims IOKit entry", r.ScenarioID)
		}
		if r.Counters["writer_generation"] == 0 {
			t.Errorf("scenario %s missing writer generation", r.ScenarioID)
		}
		if r.ScenarioID == "darwin.setup-mask-failure" && r.Counters["set_report_calls"] != 0 {
			t.Errorf("setup fault submitted native call")
		}
	}
}
