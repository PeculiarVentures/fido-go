//go:build hid_diagnostics

package hid

import (
	"fmt"
	"strings"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func validateIdenticalEvidence(result diagnostics.Result) error {
	var evidence diagnostics.Evidence
	for name, expected := range map[string]uint64{
		diagnosticKeysSelected: 2, diagnosticKeysCompleted: 2, "initial_endpoint_count": 2,
		"prompts_completed": 7, "phases_completed": 7, "unlabelled_candidate_count": 2, "initial_report_writes": 4,
		"unlabelled_automatic_open_count": 0, "unexpected_inventory_change_count": 0, "stale_neighbor_fallback_open_count": 0,
	} {
		requireIdenticalCounter(&evidence, result, name, expected)
	}
	evidence.RequireFacts(result, "initial_pair_same_descriptor", "initial_addresses_distinct", "operator_labels_from_set_difference",
		"unlabelled_recovery_ambiguous", "operator_requested_port_swap", "requests_not_replayed")
	for _, fact := range []string{"physical_identity_proven", "physical_port_topology_proven", "serial_identity_asserted", "automatic_ambiguous_recovery", "requests_replayed"} {
		requireIdenticalFact(&evidence, result, fact, false)
	}
	// Role masks describe operator-enrolled roles only: A=1, B=2. The fixed
	// phase grammar rejects contradictory removal, enrollment, and neighbor claims.
	phases := []struct {
		before, after, removed, added, neighbors, fresh, stale uint64
		removedRoles, addedRoles, neighborRoles, writes        uint64
	}{
		{2, 1, 1, 0, 1, 0, 1, 1, 0, 2, 1},
		{1, 2, 0, 1, 1, 1, 0, 0, 1, 2, 3},
		{2, 1, 1, 0, 1, 0, 1, 2, 0, 1, 1},
		{1, 2, 0, 1, 1, 1, 0, 0, 2, 1, 3},
		{2, 0, 2, 0, 0, 0, 2, 3, 0, 0, 0},
		{0, 1, 0, 1, 0, 1, 1, 0, 2, 0, 2},
		{1, 2, 0, 1, 1, 1, 0, 0, 1, 2, 3},
	}
	for index, phase := range phases {
		prefix := fmt.Sprintf("phase_%d_", index+1)
		for name, expected := range map[string]uint64{
			"before_count": phase.before, "after_count": phase.after, "removed_count": phase.removed, "added_count": phase.added,
			"neighbor_checks": phase.neighbors, "fresh_session_count": phase.fresh, "fresh_ping_count": phase.fresh,
			"stale_open_attempts": phase.stale, "stale_open_rejections": phase.stale,
			"stale_open_error_count": phase.stale, "confirmed_report_writes": phase.writes,
			"removed_role_mask": phase.removedRoles, "added_role_mask": phase.addedRoles, "neighbor_role_mask": phase.neighborRoles,
		} {
			requireIdenticalCounter(&evidence, result, prefix+name, expected)
		}
		evidence.RequireFacts(result, prefix+"inventory_complete", prefix+"expected_difference", prefix+"operator_action_observed", prefix+"retained_addresses_unchanged")
		if phase.neighbors != 0 {
			evidence.RequireFacts(result, prefix+"neighbor_same_connection", prefix+"neighbor_ping_echo_verified")
		}
		if phase.stale != 0 {
			evidence.RequireFacts(result, prefix+"stale_removed_or_stale")
		}
	}
	// A reused address is not an absent selector. Such a run must remain
	// inconclusive rather than claiming the old physical key was identified.
	requireIdenticalFact(&evidence, result, "phase_6_old_a_selector_reused_by_b", false)
	requireIdenticalFact(&evidence, result, "phase_6_stale_probe_skipped_for_address_reuse", false)
	native := platformDiagnosticCapabilities()["darwin-cgo"]
	qualifiedCloseOperations := make(map[string]bool)
	for _, role := range []string{"a", "b"} {
		rolePrefix := "role_" + role + "_"
		for name, expected := range map[string]uint64{"epochs_initialized": 3, "epochs_closed": 3, "removal_events": 2} {
			requireIdenticalCounter(&evidence, result, rolePrefix+name, expected)
		}
		evidence.RequireFacts(result, rolePrefix+"initial_ping_verified", rolePrefix+"all_epochs_closed", rolePrefix+"all_core_cleanup_done",
			rolePrefix+"all_leases_released", rolePrefix+"all_expected_close_diagnostics_qualified")
		requireIdenticalFact(&evidence, result, rolePrefix+"synthetic_call", false)
		closeErrors := uint64(0)
		for epoch := 1; epoch <= 3; epoch++ {
			prefix := fmt.Sprintf("%sepoch_%d_", rolePrefix, epoch)
			evidence.RequireFacts(result, prefix+"initialized", prefix+"fresh_init_verified", prefix+"ping_echo_verified", prefix+"closed",
				prefix+"core_cleanup_done", prefix+"endpoint_lease_released", prefix+"teardown_complete", prefix+"old_connection_rejected")
			requireIdenticalFact(&evidence, result, prefix+"synthetic_call", false)
			for _, fact := range []string{"native_probe_available", "real_probe", "same_probe", "writer_exited", "writer_joined", "device_closed"} {
				requireIdenticalFact(&evidence, result, prefix+fact, native)
			}
			removed := epoch != 3
			requireIdenticalFact(&evidence, result, prefix+"old_read_admitted", false)
			for _, fact := range []string{"old_read_observed", "absence_complete", "native_removal_error", "stale_exact_open_rejected"} {
				requireIdenticalFact(&evidence, result, prefix+fact, removed)
			}
			stale := uint64(0)
			if removed {
				stale = 1
			}
			requireIdenticalCounter(&evidence, result, prefix+"stale_open_attempts", stale)
			requireIdenticalCounter(&evidence, result, prefix+"stale_open_rejections", stale)
			success, recorded := result.Facts[prefix+"native_close_success"]
			if !recorded || (!removed && !success) {
				evidence.Errorf("missing or unexpected %snative_close_success", prefix)
			}
			expectedError := !success
			requireIdenticalFact(&evidence, result, prefix+"expected_post_removal_close_diagnostic", expectedError)
			errorCount := uint64(0)
			if expectedError {
				errorCount = 1
				closeErrors++
				if !native || !removed {
					evidence.Errorf("%s lacks native removal qualification", prefix)
				}
				qualifiedCloseOperations[prefix+"Close"] = true
			}
			requireIdenticalCounter(&evidence, result, prefix+"native_close_error_count", errorCount)
			matchedNative := uint64(0)
			for _, diagnostic := range result.NativeErrors {
				if !strings.HasPrefix(diagnostic.Operation, prefix) {
					continue
				}
				if expectedError && diagnostic.Operation == prefix+"Close" && diagnostic.Domain == "iokit" && diagnostic.Code == 0xe00002c2 {
					matchedNative++
				} else {
					evidence.Errorf("%s contains an unexpected native diagnostic", prefix)
				}
			}
			if matchedNative != errorCount {
				evidence.Errorf("%s lacks exact attributed native close evidence", prefix)
			}
		}
		requireIdenticalCounter(&evidence, result, rolePrefix+"expected_close_diagnostics", closeErrors)
		requireIdenticalCounter(&evidence, result, rolePrefix+"native_close_error_count", closeErrors)
	}
	for _, diagnostic := range result.NativeErrors {
		attributed := qualifiedCloseOperations[diagnostic.Operation]
		genericCopy := diagnostic.Operation == "HID operation" && len(qualifiedCloseOperations) != 0
		if (!attributed && !genericCopy) || diagnostic.Domain != "iokit" || diagnostic.Code != 0xe00002c2 {
			evidence.Errorf("identical-key qualification contains an unexpected native diagnostic")
		}
	}
	return evidence.Err()
}

func requireIdenticalCounter(evidence *diagnostics.Evidence, result diagnostics.Result, name string, expected uint64) {
	if actual, recorded := result.Counters[name]; !recorded || actual != expected {
		evidence.Errorf("missing or incorrect %s", name)
	}
}

func requireIdenticalFact(evidence *diagnostics.Evidence, result diagnostics.Result, name string, expected bool) {
	if actual, recorded := result.Facts[name]; !recorded || actual != expected {
		evidence.Errorf("missing or incorrect %s", name)
	}
}
