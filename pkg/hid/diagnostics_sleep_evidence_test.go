//go:build hid_diagnostics

package hid

import (
	"encoding/json"
	"fmt"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"os"
	"testing"
)

func validDiagnosticSleepEvidence(exchange bool) diagnostics.Result {
	r := diagnostics.Result{Counters: map[string]uint64{"keys_selected": 2, "keys_completed": 2}, Facts: map[string]bool{}}
	for _, f := range []string{"power_observer_ready", "power_observer_armed", "power_cycle_matched", "power_events_ordered", "power_observer_closed", "power_observer_thread_joined", "power_observer_released", "all_keys_initialized_before_sleep", "all_keys_warmed_before_sleep", "all_old_outcomes_recorded", "all_old_sessions_cleanup_complete", "all_fresh_recoveries_ping_verified", "requests_not_replayed"} {
		r.Facts[f] = true
	}
	for _, f := range []string{"native_inflight_proven", "physical_identity_proven", "requests_replayed", "power_observer_synthetic"} {
		r.Facts[f] = false
	}
	r.Facts["response_barrier_mode"] = exchange
	r.Facts["idle_sessions_quiescent"] = !exchange
	if exchange {
		r.Counters["exchanges_held_before_prompt"] = 2
		for _, f := range []string{"all_requests_submitted_before_sleep", "all_response_workers_held_before_prompt", "response_workers_joined"} {
			r.Facts[f] = true
		}
	}
	for k, v := range map[string]uint64{"operator_prompts": 1, "sleep_cycle_count": 1, "power_observer_generation": 1, "power_arm_generation": 2, "power_will_sleep_generation": 2, "power_powered_on_generation": 2, "power_sleep_sequence": 1, "power_wake_sequence": 2, "power_sleep_events": 1, "power_wake_events": 1, "power_can_sleep_events": 0, "power_canceled_events": 0, "power_out_of_order_events": 0, "power_extra_cycle_events": 0, "power_stale_events": 0, "power_ack_count": 1, "power_ack_errors": 0, "power_native_code": 0, "power_deregister_code": 0, "power_service_close_code": 0} {
		r.Counters[k] = v
	}
	frames := uint64(1)
	if exchange {
		frames = 18
	}
	for i := 1; i <= 2; i++ {
		p := fmt.Sprintf("key_%d_", i)
		for _, f := range []string{"initialized_before_sleep", "warmup_ping_verified", "old_outcome_recorded", "old_close_success", "old_cleanup_complete", "old_core_cleanup_done", "old_endpoint_lease_released", "old_writer_exited", "old_writer_joined", "old_device_closed", "fresh_inventory_complete", "unique_observed_descriptor_recovery", "fresh_init_ping_verified", "fresh_closed"} {
			r.Facts[p+f] = true
		}
		r.Facts[p+"old_echo_verified"] = true
		for _, f := range []string{"old_error_recorded", "old_error_unclassified", "physical_identity_proven", "old_close_error_recorded"} {
			r.Facts[p+f] = false
		}
		for k, v := range map[string]uint64{"old_request_attempts": 1, "old_frames_expected": frames, "old_frames_written": frames, "old_frames_read": frames, "old_error_count": 0, "old_error_categories": 0, "old_native_error_count": 0, "fresh_recovery_attempts": 1, "fresh_probe_attempts": 1, "old_native_close_errors": 0} {
			r.Counters[p+k] = v
		}
	}
	return r
}
func TestDiagnosticSleepValidatorRejectsIncompleteOrContradictoryEvidence(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "exchange"}[exchange], func(t *testing.T) {
			validate := hardwareEvidence(validateSleepEvidence(exchange))
			if err := validate(validDiagnosticSleepEvidence(exchange)); err != nil {
				t.Fatalf("valid evidence rejected: %v", err)
			}
			for _, f := range []string{"power_observer_ready", "power_cycle_matched", "power_observer_closed", "power_observer_thread_joined", "power_observer_released", "all_old_sessions_cleanup_complete", "all_fresh_recoveries_ping_verified"} {
				r := validDiagnosticSleepEvidence(exchange)
				delete(r.Facts, f)
				if validate(r) == nil {
					t.Errorf("missing %s accepted", f)
				}
			}
			for _, f := range []string{"native_inflight_proven", "physical_identity_proven", "requests_replayed", "power_observer_synthetic"} {
				r := validDiagnosticSleepEvidence(exchange)
				r.Facts[f] = true
				if validate(r) == nil {
					t.Errorf("contradictory %s accepted", f)
				}
				delete(r.Facts, f)
				if validate(r) == nil {
					t.Errorf("missing %s accepted", f)
				}
			}
			for _, counter := range []string{"power_wake_events", "power_will_sleep_generation", "power_stale_events", "power_ack_errors", "power_native_code", "power_deregister_code"} {
				r := validDiagnosticSleepEvidence(exchange)
				delete(r.Counters, counter)
				if validate(r) == nil {
					t.Errorf("missing %s accepted", counter)
				}
			}
			for _, mutate := range []func(*diagnostics.Result){func(r *diagnostics.Result) { r.Counters["keys_completed"] = 1 }, func(r *diagnostics.Result) { r.Counters["power_powered_on_generation"]++ }, func(r *diagnostics.Result) { r.Counters["power_wake_sequence"] = 1 }, func(r *diagnostics.Result) { r.Counters["power_canceled_events"] = 1 }, func(r *diagnostics.Result) { r.Counters["power_extra_cycle_events"] = 1 }, func(r *diagnostics.Result) { r.Counters["power_ack_errors"] = 1 }, func(r *diagnostics.Result) { r.Facts["key_2_old_error_recorded"] = true }, func(r *diagnostics.Result) { delete(r.Facts, "key_2_old_writer_joined") }, func(r *diagnostics.Result) { delete(r.Facts, "key_2_fresh_init_ping_verified") }, func(r *diagnostics.Result) { r.Counters["key_2_old_frames_read"]-- },
				func(r *diagnostics.Result) {
					if exchange {
						r.Counters["exchanges_held_before_prompt"] = 1
					} else {
						r.Counters["key_2_old_frames_written"] = 2
					}
				}, func(r *diagnostics.Result) { r.Counters["key_2_fresh_probe_attempts"] = 2 }, func(r *diagnostics.Result) { r.Facts["response_barrier_mode"] = !exchange }} {
				r := validDiagnosticSleepEvidence(exchange)
				mutate(&r)
				if validate(r) == nil {
					t.Error("invalid evidence accepted")
				}
			}
		})
	}
}

func TestDiagnosticSleepValidatorRequiresExplicitOldErrorClassification(t *testing.T) {
	r := validDiagnosticSleepEvidence(true)
	p := "key_1_"
	r.Facts[p+"old_echo_verified"] = false
	r.Facts[p+"old_error_recorded"] = true
	r.Counters[p+"old_error_count"] = 1
	r.Counters[p+"old_error_categories"] = 1 << 9
	r.Counters[p+"old_native_error_count"] = 1
	r.Counters[p+"old_frames_read"] = 0
	r.NativeErrors = []diagnostics.NativeError{{Operation: "key_1_old_session", Domain: "iokit", Code: 0xe00002bc}}
	validate := hardwareEvidence(validateSleepEvidence(true))
	if err := validate(r); err != nil {
		t.Fatalf("classified error rejected: %v", err)
	}
	for _, mutate := range []func(*diagnostics.Result){func(r *diagnostics.Result) { delete(r.Counters, p+"old_error_categories") }, func(r *diagnostics.Result) { r.Counters[p+"old_error_categories"] = 0 }, func(r *diagnostics.Result) { delete(r.Facts, p+"old_error_unclassified") }, func(r *diagnostics.Result) { r.NativeErrors = nil }, func(r *diagnostics.Result) { r.Counters[p+"old_native_error_count"] = 0 }, func(r *diagnostics.Result) { r.Counters[p+"old_frames_written"] = 17 }, func(r *diagnostics.Result) { r.Counters["exchanges_held_before_prompt"] = 1 }, func(r *diagnostics.Result) {
		r.Counters[p+"old_error_categories"] = 1 << 63
		r.Facts[p+"old_error_unclassified"] = false
	}} {
		copy := validDiagnosticSleepEvidence(true)
		copy.Facts[p+"old_echo_verified"] = false
		copy.Facts[p+"old_error_recorded"] = true
		copy.Counters[p+"old_error_count"] = 1
		copy.Counters[p+"old_error_categories"] = 1 << 9
		copy.Counters[p+"old_native_error_count"] = 1
		copy.Counters[p+"old_frames_read"] = 0
		copy.NativeErrors = []diagnostics.NativeError{{Operation: "key_1_old_session", Domain: "iokit", Code: 0xe00002bc}}
		mutate(&copy)
		if validate(copy) == nil {
			t.Error("incomplete or inconsistent error classification accepted")
		}
	}
}

func TestDiagnosticSleepRecordedReportEvidence(t *testing.T) {
	path := os.Getenv("FIDO_HID_DIAGNOSTICS_VERIFY_REPORT")
	if path == "" {
		t.Skip("no saved sleep report selected")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report diagnostics.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id       string
		exchange bool
	}{{"hardware.sleep-wake-idle", false}, {"hardware.sleep-wake-exchange", true}} {
		found := false
		for _, r := range report.Results {
			if r.ScenarioID != tc.id {
				continue
			}
			found = true
			if r.Status != diagnostics.Pass || !r.Cleanup.Complete {
				t.Errorf("%s status=%s cleanup=%+v", tc.id, r.Status, r.Cleanup)
			}
			if err := hardwareEvidence(validateSleepEvidence(tc.exchange))(r); err != nil {
				t.Errorf("%s invalid: %v", tc.id, err)
			}
		}
		if !found {
			t.Errorf("%s absent", tc.id)
		}
	}
}
