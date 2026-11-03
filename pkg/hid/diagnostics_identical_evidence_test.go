//go:build hid_diagnostics

package hid

import (
	"fmt"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"testing"
)

func validIdenticalEvidence() diagnostics.Result {
	r := diagnostics.Result{Counters: map[string]uint64{}, Facts: map[string]bool{}}
	for k, v := range map[string]uint64{"keys_selected": 2, "keys_completed": 2, "initial_endpoint_count": 2, "initial_report_writes": 4, "prompts_completed": 7, "phases_completed": 7, "unlabelled_candidate_count": 2, "unlabelled_automatic_open_count": 0, "unexpected_inventory_change_count": 0, "stale_neighbor_fallback_open_count": 0} {
		r.Counters[k] = v
	}
	for _, f := range []string{"initial_pair_same_descriptor", "initial_addresses_distinct", "operator_labels_from_set_difference", "unlabelled_recovery_ambiguous", "operator_requested_port_swap", "requests_not_replayed"} {
		r.Facts[f] = true
	}
	for _, f := range []string{"physical_identity_proven", "physical_port_topology_proven", "serial_identity_asserted", "automatic_ambiguous_recovery", "requests_replayed", "phase_6_old_a_selector_reused_by_b", "phase_6_stale_probe_skipped_for_address_reuse"} {
		r.Facts[f] = false
	}
	phases := [][9]uint64{{2, 1, 1, 0, 1, 0, 1, 1, 0}, {1, 2, 0, 1, 1, 1, 0, 0, 1}, {2, 1, 1, 0, 1, 0, 1, 2, 0}, {1, 2, 0, 1, 1, 1, 0, 0, 2}, {2, 0, 2, 0, 0, 0, 2, 3, 0}, {0, 1, 0, 1, 0, 1, 1, 0, 2}, {1, 2, 0, 1, 1, 1, 0, 0, 1}}
	neighborRoles := []uint64{2, 2, 1, 1, 0, 0, 2}
	writes := []uint64{1, 3, 1, 3, 0, 2, 3}
	names := []string{"before_count", "after_count", "removed_count", "added_count", "neighbor_checks", "fresh_session_count", "stale_open_attempts", "removed_role_mask", "added_role_mask"}
	for i, v := range phases {
		p := fmt.Sprintf("phase_%d_", i+1)
		for j, k := range names {
			r.Counters[p+k] = v[j]
		}
		r.Counters[p+"fresh_ping_count"] = v[5]
		r.Counters[p+"stale_open_rejections"] = v[6]
		r.Counters[p+"stale_open_error_count"] = v[6]
		r.Counters[p+"confirmed_report_writes"] = writes[i]
		r.Counters[p+"neighbor_role_mask"] = neighborRoles[i]
		for _, f := range []string{"inventory_complete", "expected_difference", "operator_action_observed", "retained_addresses_unchanged"} {
			r.Facts[p+f] = true
		}
		if v[4] > 0 {
			r.Facts[p+"neighbor_same_connection"] = true
			r.Facts[p+"neighbor_ping_echo_verified"] = true
		}
		if v[6] > 0 {
			r.Facts[p+"stale_removed_or_stale"] = true
		}
	}
	native := platformDiagnosticCapabilities()["darwin-cgo"]
	for _, role := range []string{"a", "b"} {
		p := "role_" + role + "_"
		for k, v := range map[string]uint64{"epochs_initialized": 3, "epochs_closed": 3, "removal_events": 2, "expected_close_diagnostics": 0, "native_close_error_count": 0} {
			r.Counters[p+k] = v
		}
		for _, f := range []string{"initial_ping_verified", "all_epochs_closed", "all_core_cleanup_done", "all_leases_released", "all_expected_close_diagnostics_qualified"} {
			r.Facts[p+f] = true
		}
		r.Facts[p+"synthetic_call"] = false
		for epoch := 1; epoch <= 3; epoch++ {
			e := fmt.Sprintf("%sepoch_%d_", p, epoch)
			for _, f := range []string{"initialized", "fresh_init_verified", "ping_echo_verified", "closed", "core_cleanup_done", "endpoint_lease_released", "teardown_complete", "old_connection_rejected"} {
				r.Facts[e+f] = true
			}
			r.Facts[e+"synthetic_call"] = false
			for _, f := range []string{"native_probe_available", "real_probe", "same_probe", "writer_exited", "writer_joined", "device_closed"} {
				r.Facts[e+f] = native
			}
			removed := epoch != 3
			r.Facts[e+"old_read_admitted"] = false
			for _, f := range []string{"old_read_observed", "absence_complete", "native_removal_error", "stale_exact_open_rejected"} {
				r.Facts[e+f] = removed
			}
			v := uint64(0)
			if removed {
				v = 1
			}
			r.Counters[e+"stale_open_attempts"] = v
			r.Counters[e+"stale_open_rejections"] = v
			r.Facts[e+"native_close_success"] = true
			r.Facts[e+"expected_post_removal_close_diagnostic"] = false
			r.Counters[e+"native_close_error_count"] = 0
		}
	}
	return r
}
func TestIdenticalEvidenceRejectsMissingAndContradictoryObservations(t *testing.T) {
	valid := validIdenticalEvidence()
	if err := validateIdenticalEvidence(valid); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	for _, mutate := range []func(*diagnostics.Result){func(r *diagnostics.Result) { delete(r.Counters, "phase_5_stale_open_rejections") }, func(r *diagnostics.Result) { r.Counters["phase_1_removed_role_mask"] = 2 }, func(r *diagnostics.Result) { r.Counters["phase_7_neighbor_role_mask"] = 0 }, func(r *diagnostics.Result) { delete(r.Facts, "phase_7_neighbor_same_connection") }, func(r *diagnostics.Result) { r.Counters["unlabelled_automatic_open_count"] = 1 }, func(r *diagnostics.Result) { r.Facts["physical_identity_proven"] = true }, func(r *diagnostics.Result) { r.Facts["phase_6_old_a_selector_reused_by_b"] = true }, func(r *diagnostics.Result) { delete(r.Facts, "role_b_epoch_2_writer_joined") }, func(r *diagnostics.Result) { r.Facts["role_a_epoch_1_native_removal_error"] = false }, func(r *diagnostics.Result) { r.Facts["role_a_epoch_3_synthetic_call"] = true }, func(r *diagnostics.Result) { r.Counters["role_b_epochs_closed"] = 2 }} {
		r := validIdenticalEvidence()
		mutate(&r)
		if validateIdenticalEvidence(r) == nil {
			t.Error("incomplete or contradictory identical-key evidence accepted")
		}
	}
}

func TestIdenticalEvidenceKeepsPhaseSixStaleProbeSeparateFromEpochProbe(t *testing.T) {
	for _, counter := range []string{"phase_6_stale_open_attempts", "phase_6_stale_open_rejections", "phase_6_stale_open_error_count", "role_a_epoch_2_stale_open_attempts", "role_a_epoch_2_stale_open_rejections"} {
		r := validIdenticalEvidence()
		r.Counters[counter] = 0
		if validateIdenticalEvidence(r) == nil {
			t.Errorf("missing independent %s accepted", counter)
		}
	}
	for _, fact := range []string{"phase_7_neighbor_same_connection", "phase_7_neighbor_ping_echo_verified", "phase_6_stale_removed_or_stale"} {
		r := validIdenticalEvidence()
		r.Facts[fact] = false
		if validateIdenticalEvidence(r) == nil {
			t.Errorf("missing %s accepted", fact)
		}
	}
}
func TestIdenticalEvidenceRequiresAttributedNativeCloseDiagnostic(t *testing.T) {
	if !platformDiagnosticCapabilities()["darwin-cgo"] {
		t.Skip("native close diagnostic qualification is Darwin-only")
	}
	r := validIdenticalEvidence()
	p := "role_a_epoch_1_"
	r.Facts[p+"native_close_success"] = false
	r.Facts[p+"expected_post_removal_close_diagnostic"] = true
	r.Counters[p+"native_close_error_count"] = 1
	r.Counters["role_a_expected_close_diagnostics"] = 1
	r.Counters["role_a_native_close_error_count"] = 1
	r.NativeErrors = []diagnostics.NativeError{{Operation: p + "Close", Domain: "iokit", Code: 0xe00002c2}}
	if err := validateIdenticalEvidence(r); err != nil {
		t.Fatalf("qualified close rejected: %v", err)
	}
	for _, bad := range []diagnostics.NativeError{{Operation: "HID operation", Domain: "iokit", Code: 0xe00002c2}, {Operation: p + "Close", Domain: "pthread", Code: 0xe00002c2}, {Operation: p + "Close", Domain: "iokit", Code: 1}} {
		copy := r
		copy.NativeErrors = []diagnostics.NativeError{bad}
		if validateIdenticalEvidence(copy) == nil {
			t.Error("unattributed or wrong native close error accepted")
		}
	}
	r.NativeErrors = append(r.NativeErrors, r.NativeErrors[0])
	if validateIdenticalEvidence(r) == nil {
		t.Fatal("duplicate epoch close errors accepted")
	}
}
