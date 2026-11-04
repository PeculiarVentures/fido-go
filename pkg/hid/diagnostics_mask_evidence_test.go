//go:build hid_diagnostics

package hid

import (
	"fmt"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"testing"
)

func validHardwareMaskEvidence(restore bool) diagnostics.Result {
	r := diagnostics.Result{Counters: map[string]uint64{"keys_selected": 2, "keys_completed": 2}, Facts: map[string]bool{}, NativeErrors: []diagnostics.NativeError{{Domain: "pthread", Code: 1}}}
	for _, f := range []string{"all_faults_reported", "all_retired_connections_rejected", "all_teardowns_completed", "all_fresh_session_ping_echoes_verified", "requests_not_replayed"} {
		r.Facts[f] = true
	}
	for i := 1; i <= 2; i++ {
		p := fmt.Sprintf("key_%d_", i)
		for _, f := range []string{"fresh_channel_initialized", "fault_armed_after_init", "fault_error_retained", "old_connection_rejected", "old_generation_no_more_submissions", "core_cleanup_done", "endpoint_lease_released", "writer_exited", "writer_joined", "device_closed", "no_generation_reuse", "fresh_session_initialized", "fresh_session_ping_echo_verified", "fresh_native_completed", "fresh_mask_restored", "fresh_writer_joined", "fresh_device_closed", "requests_not_replayed", "before_unrelated_blocked", "after_unrelated_blocked"} {
			r.Facts[p+f] = true
		}
		for _, f := range []string{"synthetic_call", "fresh_synthetic_call", "failed_session_ping_echo_verified", "before_sigurg_blocked"} {
			r.Facts[p+f] = false
		}
		r.Facts[p+"submitted"] = restore
		r.Facts[p+"completed"] = restore
		r.Facts[p+"mask_restored"] = !restore
		r.Facts[p+"after_sigurg_blocked"] = restore
		c := map[string]uint64{"writer_generation": uint64(2*i - 1), "fresh_writer_generation": uint64(2 * i), "writes": 1, "native_result_code": 0, "initial_mask_error": 0, "mask_query_error": 0, "fault_error_code": 1, "fresh_set_report_calls": 1}
		if restore {
			c["set_report_calls"] = 1
			c["write_outcome"] = uint64(OutcomeCompleted)
			c["setup_error"] = 0
			c["restore_error"] = 1
			for _, f := range []string{"completed_outcome_preserved", "protected_mask_retained_after_restore_failure", "critical_sigurg_blocked"} {
				r.Facts[p+f] = true
			}
		} else {
			c["set_report_calls"] = 0
			c["write_outcome"] = uint64(OutcomeNotSubmitted)
			c["setup_error"] = 1
			c["restore_error"] = 0
			r.Facts[p+"setup_failed_not_submitted"] = true
			r.Facts[p+"original_mask_intact"] = true
		}
		for k, v := range c {
			r.Counters[p+k] = v
		}
	}
	return r
}
func TestHardwareMaskValidatorsRejectIncompleteOrContradictoryEvidence(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "setup", true: "restore"}[restore], func(t *testing.T) {
			validate := hardwareEvidence(hardwareMaskFailureEvidence(restore))
			if err := validate(validHardwareMaskEvidence(restore)); err != nil {
				t.Fatalf("valid evidence rejected: %v", err)
			}
			for _, f := range []string{"fault_armed_after_init", "fault_error_retained", "old_connection_rejected", "core_cleanup_done", "endpoint_lease_released", "writer_exited", "writer_joined", "device_closed", "fresh_session_ping_echo_verified", "fresh_mask_restored", "requests_not_replayed"} {
				r := validHardwareMaskEvidence(restore)
				delete(r.Facts, "key_2_"+f)
				if validate(r) == nil {
					t.Errorf("missing key 2 %s accepted", f)
				}
			}
			for _, f := range []string{"synthetic_call", "fresh_synthetic_call", "failed_session_ping_echo_verified", "before_sigurg_blocked"} {
				missing := validHardwareMaskEvidence(restore)
				delete(missing.Facts, "key_1_"+f)
				if validate(missing) == nil {
					t.Errorf("missing explicit false %s accepted", f)
				}
				r := validHardwareMaskEvidence(restore)
				r.Facts["key_1_"+f] = true
				if validate(r) == nil {
					t.Errorf("contradictory %s accepted", f)
				}
			}
			for _, counter := range []string{"set_report_calls", "write_outcome", "setup_error", "restore_error", "native_result_code", "mask_query_error", "fault_error_code", "fresh_set_report_calls"} {
				r := validHardwareMaskEvidence(restore)
				delete(r.Counters, "key_1_"+counter)
				if validate(r) == nil {
					t.Errorf("missing %s accepted", counter)
				}
			}
			for _, mutate := range []func(*diagnostics.Result){func(r *diagnostics.Result) { r.Counters["keys_completed"] = 1 }, func(r *diagnostics.Result) { r.Counters["key_1_writer_generation"] = 0 }, func(r *diagnostics.Result) {
				r.Counters["key_2_fresh_writer_generation"] = r.Counters["key_1_writer_generation"]
			}, func(r *diagnostics.Result) { r.NativeErrors = nil }, func(r *diagnostics.Result) { r.Counters["key_1_set_report_calls"]++ }, func(r *diagnostics.Result) { r.Facts["key_1_submitted"] = !restore }, func(r *diagnostics.Result) { r.Facts["key_1_mask_restored"] = restore }} {
				r := validHardwareMaskEvidence(restore)
				mutate(&r)
				if validate(r) == nil {
					t.Error("contradictory evidence accepted")
				}
			}
		})
	}
}
