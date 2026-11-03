//go:build hid_diagnostics

package hid

import "github.com/PeculiarVentures/fido-go/internal/diagnostics"

// EPERM is one on Darwin. Keep the deliberate shim fault fixed and explicit in
// the platform-independent evidence contract, rather than accepting any error.
const diagnosticMaskFaultCode = 1

func hardwareMaskFailureEvidence(restore bool) func(diagnostics.Result) error {
	return func(r diagnostics.Result) error {
		var evidence diagnostics.Evidence
		evidence.RequireFacts(r, "all_faults_reported", "all_retired_connections_rejected", "all_teardowns_completed", "all_fresh_session_ping_echoes_verified", "requests_not_replayed")
		seenGeneration := make(map[uint64]bool)
		for ordinal := uint64(1); ordinal <= r.Counters[diagnosticKeysSelected]; ordinal++ {
			prefix := diagnosticKeyPrefix(ordinal)
			for _, fact := range []string{
				"fresh_channel_initialized", "fault_armed_after_init", "fault_error_retained", "old_connection_rejected", "old_generation_no_more_submissions",
				"core_cleanup_done", "endpoint_lease_released", "writer_exited", "writer_joined", "device_closed", "no_generation_reuse",
				"fresh_session_initialized", "fresh_session_ping_echo_verified", "fresh_native_completed", "fresh_mask_restored", "fresh_writer_joined", "fresh_device_closed",
				"requests_not_replayed", "before_unrelated_blocked", "after_unrelated_blocked",
			} {
				evidence.RequireFacts(r, prefix+fact)
			}
			expectedFacts := map[string]bool{
				"synthetic_call": false, "fresh_synthetic_call": false, "failed_session_ping_echo_verified": false, "before_sigurg_blocked": false,
				"submitted": restore, "completed": restore, "mask_restored": !restore, "after_sigurg_blocked": restore,
			}
			calls, setupCode, restoreCode, outcome := uint64(0), uint64(diagnosticMaskFaultCode), uint64(0), uint64(OutcomeNotSubmitted)
			if restore {
				calls, setupCode, restoreCode, outcome = 1, 0, diagnosticMaskFaultCode, uint64(OutcomeCompleted)
				evidence.RequireFacts(r, prefix+"completed_outcome_preserved", prefix+"protected_mask_retained_after_restore_failure", prefix+"critical_sigurg_blocked")
			} else {
				evidence.RequireFacts(r, prefix+"setup_failed_not_submitted", prefix+"original_mask_intact")
			}
			for fact, expected := range expectedFacts {
				if actual, recorded := r.Facts[prefix+fact]; !recorded || actual != expected {
					evidence.Errorf("key %d missing or incorrect %s", ordinal, fact)
				}
			}
			for counter, expected := range map[string]uint64{
				"set_report_calls": calls, "writes": 1, "write_outcome": outcome, "setup_error": setupCode, "restore_error": restoreCode,
				"native_result_code": 0, "initial_mask_error": 0, "mask_query_error": 0, "fault_error_code": diagnosticMaskFaultCode, "fresh_set_report_calls": 1,
			} {
				if actual, recorded := r.Counters[prefix+counter]; !recorded || actual != expected {
					evidence.Errorf("key %d missing or incorrect %s", ordinal, counter)
				}
			}
			old, fresh := r.Counters[prefix+diagnosticWriterGeneration], r.Counters[prefix+"fresh_writer_generation"]
			if old == 0 || fresh <= old || seenGeneration[old] || seenGeneration[fresh] {
				evidence.Errorf("key %d lacks independent writer generations", ordinal)
			}
			seenGeneration[old], seenGeneration[fresh] = true, true
		}
		faultRecorded := false
		for _, native := range r.NativeErrors {
			if native.Domain == "pthread" && native.Code == diagnosticMaskFaultCode {
				faultRecorded = true
			}
		}
		if !faultRecorded {
			evidence.Errorf("mask-fault native errno is absent")
		}
		return evidence.Err()
	}
}
