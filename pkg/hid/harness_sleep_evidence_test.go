//go:build hid_diagnostics

package hid

import "github.com/PeculiarVentures/fido-go/internal/diagnostics"

func validateSleepEvidence(exchange bool) func(diagnostics.Result) error {
	return func(r diagnostics.Result) error {
		var e diagnostics.Evidence
		keys := r.Counters[diagnosticKeysSelected]
		if keys < 2 {
			e.Errorf("sleep cycle did not cover at least two selected keys")
		}
		e.RequireFacts(r, "power_observer_ready", "power_observer_armed", "power_cycle_matched", "power_events_ordered", "power_observer_closed", "power_observer_thread_joined", "power_observer_released", "all_keys_initialized_before_sleep", "all_keys_warmed_before_sleep", "all_old_outcomes_recorded", "all_old_sessions_cleanup_complete", "all_fresh_recoveries_ping_verified", "requests_not_replayed")
		for _, name := range []string{"native_inflight_proven", "physical_identity_proven", "requests_replayed", "power_observer_synthetic"} {
			value, recorded := r.Facts[name]
			if !recorded || value {
				e.Errorf("sleep scenario has missing or invalid %s", name)
			}
		}
		if r.Counters["operator_prompts"] != 1 || r.Counters["sleep_cycle_count"] != 1 {
			e.Errorf("sleep scenario did not use exactly one operator prompt and cycle")
		}
		requiredCounters := []string{"power_observer_generation", "power_arm_generation", "power_will_sleep_generation", "power_powered_on_generation", "power_sleep_sequence", "power_wake_sequence", "power_sleep_events", "power_wake_events", "power_can_sleep_events", "power_canceled_events", "power_out_of_order_events", "power_extra_cycle_events", "power_stale_events", "power_ack_count", "power_ack_errors", "power_native_code", "power_deregister_code", "power_service_close_code"}
		for _, name := range requiredCounters {
			if _, recorded := r.Counters[name]; !recorded {
				e.Errorf("missing sleep counter %s", name)
			}
		}
		generation := r.Counters["power_arm_generation"]
		if r.Counters["power_observer_generation"] == 0 || generation == 0 || r.Counters["power_will_sleep_generation"] != generation || r.Counters["power_powered_on_generation"] != generation {
			e.Errorf("sleep notifications do not match the armed observer generation")
		}
		if r.Counters["power_sleep_sequence"] == 0 || r.Counters["power_wake_sequence"] <= r.Counters["power_sleep_sequence"] {
			e.Errorf("sleep and wake notifications were not observed in order")
		}
		if r.Counters["power_sleep_events"] != 1 || r.Counters["power_wake_events"] != 1 {
			e.Errorf("sleep scenario did not observe exactly one actual sleep/wake pair")
		}
		for _, name := range []string{"power_canceled_events", "power_out_of_order_events", "power_extra_cycle_events", "power_stale_events", "power_ack_errors", "power_native_code", "power_deregister_code", "power_service_close_code"} {
			if r.Counters[name] != 0 {
				e.Errorf("sleep observer reported %s", name)
			}
		}
		if r.Counters["power_ack_count"] < r.Counters["power_sleep_events"]+r.Counters["power_can_sleep_events"] {
			e.Errorf("power notifications were not all acknowledged")
		}
		mode, modeRecorded := r.Facts["response_barrier_mode"]
		quiescent, quiescentRecorded := r.Facts["idle_sessions_quiescent"]
		if !modeRecorded || mode != exchange || !quiescentRecorded || quiescent == exchange {
			e.Errorf("sleep evidence mislabeled idle versus response-barrier mode")
		}
		if exchange {
			e.RequireFacts(r, "all_requests_submitted_before_sleep", "all_response_workers_held_before_prompt", "response_workers_joined")
			if r.Counters["exchanges_held_before_prompt"] != keys {
				e.Errorf("not every selected exchange was held before the prompt")
			}
		}
		expected := uint64(1)
		if exchange {
			expected = 18
		}
		for ordinal := uint64(1); ordinal <= keys; ordinal++ {
			p := diagnosticKeyPrefix(ordinal)
			for _, name := range []string{"old_request_attempts", "old_frames_expected", "old_frames_written", "old_frames_read", "old_error_count", "old_error_categories", "old_native_error_count", "fresh_recovery_attempts", "fresh_probe_attempts", "old_native_close_errors"} {
				if _, recorded := r.Counters[p+name]; !recorded {
					e.Errorf("key %d missing %s", ordinal, name)
				}
			}
			e.RequireFacts(r, p+"initialized_before_sleep", p+"warmup_ping_verified", p+"old_outcome_recorded", p+"old_close_success", p+"old_cleanup_complete", p+"old_core_cleanup_done", p+"old_endpoint_lease_released", p+"old_writer_exited", p+"old_writer_joined", p+"old_device_closed", p+"fresh_inventory_complete", p+"unique_observed_descriptor_recovery", p+"fresh_init_ping_verified", p+"fresh_closed")
			echo, echoRecorded := r.Facts[p+"old_echo_verified"]
			failed, errorRecorded := r.Facts[p+"old_error_recorded"]
			if !echoRecorded || !errorRecorded || echo == failed {
				e.Errorf("key %d did not record exactly one old-session outcome", ordinal)
			}
			if r.Counters[p+"old_request_attempts"] != 1 || r.Counters[p+"old_frames_expected"] != expected {
				e.Errorf("key %d old request count or format is invalid", ordinal)
			}
			if echo && (r.Counters[p+"old_frames_written"] != expected || r.Counters[p+"old_frames_read"] != expected || r.Counters[p+"old_error_count"] != 0) {
				e.Errorf("key %d old echo lacks complete original frames", ordinal)
			}
			if exchange && r.Counters[p+"old_frames_written"] != expected || r.Counters[p+"old_frames_written"] > expected || r.Counters[p+"old_frames_read"] > expected {
				e.Errorf("key %d contradicts the request barrier or report format", ordinal)
			}
			classes := r.Counters[p+"old_error_categories"]
			unclassified, classificationRecorded := r.Facts[p+"old_error_unclassified"]
			if !classificationRecorded || unclassified != (classes == diagnosticSleepUnclassified) || classes & ^(diagnosticSleepKnownErrors|diagnosticSleepUnclassified) != 0 || classes&diagnosticSleepUnclassified != 0 && classes != diagnosticSleepUnclassified || failed && classes == 0 || echo && classes != 0 {
				e.Errorf("key %d missing or contradictory old error classification", ordinal)
			}
			nativeCodes := make(map[struct {
				domain string
				code   uint64
			}]bool)
			for _, native := range r.NativeErrors {
				if native.Operation == p+"old_session" {
					nativeCodes[struct {
						domain string
						code   uint64
					}{native.Domain, native.Code}] = true
				}
			}
			if uint64(len(nativeCodes)) != r.Counters[p+"old_native_error_count"] || echo && r.Counters[p+"old_native_error_count"] != 0 {
				e.Errorf("key %d native old error evidence is inconsistent", ordinal)
			}
			if failed && r.Counters[p+"old_error_count"] != 1 {
				e.Errorf("key %d old-session failure lacks an explicit error count", ordinal)
			}
			if r.Counters[p+"fresh_recovery_attempts"] != 1 || r.Counters[p+"fresh_probe_attempts"] != 1 || r.Counters[p+"old_native_close_errors"] != 0 {
				e.Errorf("key %d fresh recovery or old close evidence is invalid", ordinal)
			}
			for _, name := range []string{"physical_identity_proven", "old_close_error_recorded"} {
				value, recorded := r.Facts[p+name]
				if !recorded || value {
					e.Errorf("key %d missing or invalid %s", ordinal, name)
				}
			}
		}
		return e.Err()
	}
}
