//go:build hid_diagnostics

package usb_test

import (
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
)

func usbSleepEvidence(exchange bool) func(diagnostics.Result) error {
	return func(r diagnostics.Result) error {
		var e diagnostics.Evidence
		keys := r.Counters["keys_selected"]
		if keys != 2 || r.Counters["keys_completed"] != keys {
			e.Errorf("USB sleep did not complete both selected keys")
		}
		e.RequireFacts(r, "production_usb_api", "all_warmup_pings_verified", "all_old_outcomes_recorded", "all_old_sessions_closed", "all_fresh_recoveries_ping_verified", "requests_not_replayed", "production_callers_joined")
		usbSleepFact(&e, r, "native_inflight_proven", false)
		usbSleepFact(&e, r, "physical_identity_proven", false)
		usbSleepFact(&e, r, "response_barrier_mode", exchange)
		usbSleepFact(&e, r, "idle_sessions_quiescent", !exchange)
		if r.Counters["operator_prompts"] != 1 || r.Counters["sleep_cycle_count"] != 1 {
			e.Errorf("USB sleep did not use one prompt and cycle for both keys")
		}
		workers := uint64(0)
		if exchange {
			workers = keys
			e.RequireFacts(r, "all_requests_submitted_before_sleep", "all_response_reads_held_before_prompt")
		}
		for _, name := range []string{"caller_workers_started", "caller_workers_joined", "response_barriers_entered"} {
			usbSleepCounter(&e, r, name, workers)
		}
		validateUSBSleepPower(&e, r)
		expected := uint64(1)
		if exchange {
			expected = 18
		}
		for index := uint64(1); index <= keys; index++ {
			p := usbSleepKey(int(index))
			e.RequireFacts(r, p+"warmup_ping_verified", p+"old_close_success", p+"fresh_discovery_complete", p+"recovery_metadata_verified", p+"fresh_init_ping_verified", p+"fresh_closed")
			for _, name := range []string{"physical_identity_proven", "old_close_error_recorded"} {
				usbSleepFact(&e, r, p+name, false)
			}
			usbSleepCounter(&e, r, p+"old_close_errors", 0)
			usbSleepCounter(&e, r, p+"fresh_probe_attempts", 1)
			exact, exactRecorded := r.Facts[p+"recovery_exact_retained"]
			unique, uniqueRecorded := r.Facts[p+"recovery_unique_unclaimed"]
			if !exactRecorded || !uniqueRecorded || exact == unique {
				e.Errorf("key %d lacks one safe recovery resolution", index)
			}
			usbSleepFact(&e, r, p+"response_read_entered_before_prompt", exchange)
			usbSleepFact(&e, r, p+"response_read_held_until_wake", exchange)
			before := uint64(0)
			if exchange {
				before = 18
			}
			usbSleepCounter(&e, r, p+"confirmed_writes_before_prompt", before)
			usbSleepCounter(&e, r, p+"forwarded_raw_reads_before_wake", 0)
			for _, name := range []string{"old_confirmed_writes", "old_expected_writes", "old_error_count", "old_error_categories", "old_native_error_count", "old_exchange_stage", "old_packets_submitted", "old_write_outcome"} {
				if _, present := r.Counters[p+name]; !present {
					e.Errorf("key %d missing %s", index, name)
				}
			}
			usbSleepCounter(&e, r, p+"old_expected_writes", expected)
			written := r.Counters[p+"old_confirmed_writes"]
			if written > expected || exchange && written != expected {
				e.Errorf("key %d write count contradicts the production response barrier", index)
			}
			echo, echoPresent := r.Facts[p+"old_echo_verified"]
			failed, failedPresent := r.Facts[p+"old_error_recorded"]
			if !echoPresent || !failedPresent || echo == failed {
				e.Errorf("key %d lacks exactly one old production exchange outcome", index)
			}
			typed, typedPresent := r.Facts[p+"old_exchange_error_present"]
			ambiguous, ambiguousPresent := r.Facts[p+"old_delivery_ambiguous"]
			if !typedPresent || !ambiguousPresent {
				e.Errorf("key %d lacks typed delivery metadata", index)
			}
			stage, outcome, packets := r.Counters[p+"old_exchange_stage"], r.Counters[p+"old_write_outcome"], r.Counters[p+"old_packets_submitted"]
			if packets != written || outcome > uint64(hid.OutcomeCompleted) {
				e.Errorf("key %d delivery evidence contradicts completed native writes", index)
			}
			if echo && (typed || ambiguous || stage != 0 || outcome != uint64(hid.OutcomeCompleted) || written != expected) {
				e.Errorf("key %d successful echo has invalid delivery evidence", index)
			}
			if failed && (!typed || stage < 3 || stage > 4 || exchange && stage != 4) {
				e.Errorf("key %d failure lacks the expected production exchange stage", index)
			}
			if failed && stage == 4 && (written != expected || outcome != uint64(hid.OutcomeCompleted)) {
				e.Errorf("key %d response stage contradicts completed request delivery", index)
			}
			if failed && stage == 3 && (outcome == uint64(hid.OutcomeCompleted) && written == 0 || outcome != uint64(hid.OutcomeCompleted) && written != 0) {
				e.Errorf("key %d single-report request outcome contradicts write completion", index)
			}
			if failed && (outcome == uint64(hid.OutcomeUnknown) || stage == 3 && written > 0) && !ambiguous {
				e.Errorf("key %d lost delivery uncertainty", index)
			}
			if failed && stage == 3 && outcome == uint64(hid.OutcomeNotSubmitted) && written == 0 && ambiguous {
				e.Errorf("key %d labels a proven unsubmitted request as uncertain", index)
			}

			count := uint64(0)
			if failed {
				count = 1
			}
			usbSleepCounter(&e, r, p+"old_error_count", count)
			classes := r.Counters[p+"old_error_categories"]
			unknown, unknownPresent := r.Facts[p+"old_error_unclassified"]
			if !unknownPresent || unknown != (classes == usbSleepUnknownError) || classes & ^(usbSleepKnownErrors|usbSleepUnknownError) != 0 || classes&usbSleepUnknownError != 0 && classes != usbSleepUnknownError || failed && classes == 0 || echo && classes != 0 {
				e.Errorf("key %d has missing or contradictory error classification", index)
			}
			native := make(map[usbSleepNativeCode]bool)
			for _, code := range r.NativeErrors {
				if code.Operation == p+"old_exchange" {
					native[usbSleepNativeCode{code.Domain, code.Code}] = true
				}
			}
			if uint64(len(native)) != r.Counters[p+"old_native_error_count"] || echo && len(native) != 0 {
				e.Errorf("key %d native exchange errors are not preserved", index)
			}
			transportClass := uint64((1 << 9) | (1 << 11) | (1 << 12))
			if failed && stage == 4 && (len(native) > 0 || classes&transportClass != 0) && !ambiguous {
				e.Errorf("key %d response transport failure lost command uncertainty", index)
			}

		}
		return e.Err()
	}
}

func validateUSBSleepPower(e *diagnostics.Evidence, r diagnostics.Result) {
	e.RequireFacts(r, "power_observer_ready", "power_observer_armed", "power_cycle_matched", "power_events_ordered", "power_observer_closed", "power_observer_thread_joined", "power_observer_released")
	usbSleepFact(e, r, "power_observer_synthetic", false)
	for _, name := range []string{"power_observer_generation", "power_arm_generation", "power_will_sleep_generation", "power_powered_on_generation", "power_sleep_sequence", "power_wake_sequence", "power_can_sleep_events", "power_sleep_events", "power_wake_events", "power_canceled_events", "power_out_of_order_events", "power_extra_cycle_events", "power_stale_events", "power_ack_count", "power_ack_errors", "power_native_code", "power_deregister_code", "power_service_close_code"} {
		if _, present := r.Counters[name]; !present {
			e.Errorf("missing power evidence %s", name)
		}
	}
	generation := r.Counters["power_arm_generation"]
	if r.Counters["power_observer_generation"] == 0 || generation == 0 || r.Counters["power_will_sleep_generation"] != generation || r.Counters["power_powered_on_generation"] != generation {
		e.Errorf("USB power events do not match one armed generation")
	}
	if r.Counters["power_sleep_sequence"] == 0 || r.Counters["power_wake_sequence"] <= r.Counters["power_sleep_sequence"] {
		e.Errorf("USB power event order is invalid")
	}
	usbSleepCounter(e, r, "power_sleep_events", 1)
	usbSleepCounter(e, r, "power_wake_events", 1)
	for _, name := range []string{"power_canceled_events", "power_out_of_order_events", "power_extra_cycle_events", "power_stale_events", "power_ack_errors", "power_native_code", "power_deregister_code", "power_service_close_code"} {
		usbSleepCounter(e, r, name, 0)
	}
	if r.Counters["power_ack_count"] < r.Counters["power_sleep_events"]+r.Counters["power_can_sleep_events"] {
		e.Errorf("USB power notifications were not all acknowledged")
	}
}
func usbSleepFact(e *diagnostics.Evidence, r diagnostics.Result, name string, expected bool) {
	if value, present := r.Facts[name]; !present || value != expected {
		e.Errorf("missing or invalid %s", name)
	}
}
func usbSleepCounter(e *diagnostics.Evidence, r diagnostics.Result, name string, expected uint64) {
	if value, present := r.Counters[name]; !present || value != expected {
		e.Errorf("missing or invalid %s", name)
	}
}
