//go:build hid_diagnostics && integration

package hid

import (
	"fmt"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"strings"
	"testing"
)

func assertSelectedHardwareDiagnostics(t *testing.T, report diagnostics.Report, opts hidDiagnosticsOptions) {
	t.Helper()
	results := map[string]diagnostics.Result{}
	for _, r := range report.Results {
		if _, exists := results[r.ScenarioID]; exists {
			t.Errorf("duplicate scenario %s", r.ScenarioID)
		}
		results[r.ScenarioID] = r
		if r.Status == diagnostics.Fail {
			t.Errorf("scenario %s failed: %s", r.ScenarioID, r.Reason)
		}
	}
	requested := func(id string) bool {
		if len(opts.ScenarioIDs) == 0 {
			return true
		}
		for _, v := range opts.ScenarioIDs {
			if v == id {
				return true
			}
		}
		return false
	}
	if len(opts.ScenarioIDs) == 0 {
		requireDiagnosticScenarios(t, report, expectedDeterministicDiagnosticIDs())
		assertNativeDiagnosticEvidence(t, report)
	} else {
		for _, id := range opts.ScenarioIDs {
			r, ok := results[id]
			if !ok {
				t.Errorf("selected scenario %q absent", id)
				continue
			}
			if !strings.HasPrefix(id, "hardware.") && (r.Status != diagnostics.Pass || !r.Cleanup.Complete) {
				t.Errorf("selected scenario %s did not pass: %s", id, r.Status)
			}
		}
	}
	var selected uint64
	for _, id := range []string{"hardware.sigurg-ping", "hardware.multiframe-ping", "hardware.parallel-exchange", "hardware.cancel-close", "hardware.unplug-replug", "hardware.strict-iokit-entry"} {
		if !requested(id) {
			continue
		}
		r, ok := results[id]
		if !ok {
			t.Errorf("scenario %s absent", id)
			continue
		}
		optional := (id == "hardware.strict-iokit-entry" && !opts.StrictIOKit) || (id == "hardware.unplug-replug" && !opts.InteractiveUnplug)
		if optional {
			if r.Status != diagnostics.Skip {
				t.Errorf("unrequested %s status=%s", id, r.Status)
			}
			continue
		}
		if (id == "hardware.sigurg-ping" || id == "hardware.strict-iokit-entry") && !supplementalNativeWriteAvailable() && (r.Status == diagnostics.Inconclusive || r.Status == diagnostics.Skip) {
			if len(opts.ScenarioIDs) > 0 {
				t.Skipf("native signal probe unavailable: %s", r.Reason)
			}
			continue
		}
		if id == "hardware.strict-iokit-entry" && (r.Status == diagnostics.Inconclusive || r.Status == diagnostics.Skip) {
			if r.Facts["all_native_entries_confirmed"] {
				t.Error("unconfirmed IOKit entry incorrectly recorded")
			}
			t.Skipf("strict IOKit-entry evidence unavailable: %s", r.Reason)
		}
		if r.Status != diagnostics.Pass || !r.Cleanup.Complete {
			t.Errorf("scenario %s status=%s cleanup=%+v reason=%s", id, r.Status, r.Cleanup, r.Reason)
			continue
		}
		keys := r.Counters["keys_selected"]
		if keys == 0 || r.Counters["keys_completed"] != keys || len(opts.EndpointIDs) > 0 && keys != uint64(len(opts.EndpointIDs)) {
			t.Errorf("scenario %s incomplete keys selected=%d completed=%d", id, keys, r.Counters["keys_completed"])
			continue
		}
		if selected != 0 && selected != keys {
			t.Errorf("scenario %s selected %d keys, expected %d", id, keys, selected)
		}
		selected = keys
		if id == "hardware.sigurg-ping" || id == "hardware.strict-iokit-entry" {
			assertSignalEvidence(t, id, r, keys)
		}
		assertExtendedHardwareEvidence(t, id, r, keys)
	}
}
func assertSignalEvidence(t *testing.T, id string, r diagnostics.Result, keys uint64) {
	t.Helper()
	strict := id == "hardware.strict-iokit-entry"
	facts := []string{"all_ping_echoes_verified", "all_native_submissions_completed", "all_masks_restored"}
	if strict {
		facts = append(facts, "all_native_entries_confirmed")
	} else {
		facts = append(facts, "all_signals_pending_before_real_call")
	}
	for _, f := range facts {
		if !r.Facts[f] {
			t.Errorf("scenario %s missing %s", id, f)
		}
	}
	for i := uint64(1); i <= keys; i++ {
		p := fmt.Sprintf("key_%d_", i)
		facts := []string{"ping_echo_verified", "native_submission_completed", "mask_restored", "writer_joined"}
		if strict {
			facts = append(facts, "native_entry_confirmed", "entry_sigurg_blocked", "entry_pending_sigurg")
		} else {
			facts = append(facts, "pending_before_real_call")
			if r.Facts[p+"native_entry_confirmed"] {
				t.Errorf("key %d mislabels native entry", i)
			}
		}
		for _, f := range facts {
			if !r.Facts[p+f] {
				t.Errorf("scenario %s key %d missing %s", id, i, f)
			}
		}
		gen := r.Counters[p+"writer_generation"]
		if gen == 0 || gen != r.Counters[p+"kill_generation"] || strict && gen != r.Counters[p+"entry_generation"] || r.Facts[p+"synthetic_call"] {
			t.Errorf("scenario %s key %d generation mismatch", id, i)
		}
	}
}

func assertExtendedHardwareEvidence(t *testing.T, id string, r diagnostics.Result, keys uint64) {
	t.Helper()
	var all, per []string
	switch id {
	case "hardware.multiframe-ping":
		all = []string{"all_payload_echoes_verified", "all_frame_counts_verified", "requests_not_replayed"}
		per = []string{"fresh_channel_initialized", "closed"}
		if r.Counters["payload_cases_per_key"] != 5 {
			t.Errorf("multiframe case count=%d", r.Counters["payload_cases_per_key"])
		}
		for i := uint64(1); i <= keys; i++ {
			prefix := fmt.Sprintf("key_%d_", i)
			if r.Counters[prefix+"payload_cases_completed"] != 5 {
				t.Errorf("key %d incomplete payload cases", i)
			}
			for _, size := range []int{0, 57, 58, 128, 1024} {
				p := fmt.Sprintf("%spayload_%d_", prefix, size)
				expected := uint64(1)
				if size > 57 {
					expected += uint64((size - 57 + 58) / 59)
				}
				if !r.Facts[p+"echo_verified"] || !r.Facts[p+"native_writes_completed"] || r.Counters[p+"frames_expected"] != expected || r.Counters[p+"frames_written"] != expected || r.Counters[p+"frames_read"] != expected {
					t.Errorf("key %d payload %d incomplete echo/frames", i, size)
				}
			}
		}
	case "hardware.parallel-exchange":
		all = []string{"independent_endpoint_addresses", "workers_ready_before_start", "all_requests_submitted_at_response_barrier", "complete_inventory_during_overlap", "parallel_workers_joined", "all_payload_echoes_verified", "all_responses_isolated", "requests_not_replayed"}
		per = []string{"response_isolated", "echo_verified"}
		if keys < 2 || r.Counters["max_overlapping_exchanges"] < keys || r.Counters["inventory_polls_completed"] < 2 {
			t.Errorf("parallel overlap/inventory evidence incomplete")
		}
		for i := uint64(1); i <= keys; i++ {
			p := fmt.Sprintf("key_%d_", i)
			if r.Counters[p+"frames_expected"] != 18 || r.Counters[p+"frames_written"] != 18 || r.Counters[p+"frames_read"] != 18 {
				t.Errorf("parallel key %d missing frames", i)
			}
		}
	case "hardware.cancel-close":
		all = []string{"all_admitted_reads_canceled", "all_old_connections_reject_reuse", "all_bounded_closes_observed", "all_native_cleanups_completed", "all_fresh_reopens_ping_verified"}
		per = []string{"read_admitted", "read_canceled", "read_native_cleanup", "close_read_admitted", "close_read_completed", "fresh_reopen_ping"}
		if supplementalNativeWriteAvailable() {
			all = append(all, "protected_before_iokit_barrier", "native_write_stage_available")
			per = append(per, "write_admitted", "write_canceled", "close_deadline_observed", "cleanup_deferred", "writer_joined", "device_closed")
		} else {
			all = append(all, "native_write_stage_skipped")
			per = append(per, "native_write_stage_skipped")
		}
		for i := uint64(1); i <= keys; i++ {
			if supplementalNativeWriteAvailable() && r.Counters[fmt.Sprintf("key_%d_native_submissions", i)] != 1 {
				t.Errorf("cancel key %d missing single native submission", i)
			}
		}
		if r.Facts["actual_kernel_inflight_cancellation"] || r.Facts["requests_replayed"] || supplementalNativeWriteAvailable() && r.Facts["native_write_stage_skipped"] {
			t.Errorf("cancel scenario claims unobserved kernel cancellation or replay")
		}
	case "hardware.unplug-replug":
		per = []string{"old_read_admitted", "absence_complete", "old_connection_error_observed", "old_connection_closed", "teardown_complete", "core_cleanup_done", "endpoint_lease_released", "stale_exact_open_rejected", "neighbors_ping_verified", "reappearance_complete", "unique_observed_descriptor_recovery", "fresh_init_ping_verified"}
		for i := uint64(1); i <= keys; i++ {
			p := fmt.Sprintf("key_%d_", i)
			nativeCloseSuccess, recorded := r.Facts[p+"native_close_success"]
			if !recorded {
				t.Errorf("hotplug key %d missing native close outcome", i)
			}
			if recorded && !nativeCloseSuccess {
				found := false
				for _, n := range r.NativeErrors {
					if n.Domain == "iokit" && n.Code == 0xe00002c2 {
						found = true
					}
				}
				if !r.Facts[p+"expected_post_removal_close_diagnostic"] || !r.Facts[p+"writer_exited"] || !r.Facts[p+"writer_joined"] || !r.Facts[p+"device_closed"] || !found {
					t.Errorf("hotplug key %d missing explicit native close diagnostic", i)
				}
			}
			if r.Facts[p+"physical_identity_proven"] || r.Counters[p+"neighbors_verified"] < keys-1 {
				t.Errorf("hotplug key %d identity or neighbor evidence invalid", i)
			}
		}
		all = []string{"all_absences_complete", "all_stale_exact_opens_rejected", "all_neighbors_ping_verified", "all_recoveries_ping_verified", "manual_same_port_reconnect_requested"}
		if r.Facts["physical_identity_proven"] || r.Facts["requests_replayed"] {
			t.Error("hotplug scenario overclaims physical identity")
		}
	}
	for _, f := range all {
		if !r.Facts[f] {
			t.Errorf("scenario %s missing %s", id, f)
		}
	}
	for i := uint64(1); i <= keys; i++ {
		prefix := fmt.Sprintf("key_%d_", i)
		for _, f := range per {
			if !r.Facts[prefix+f] {
				t.Errorf("scenario %s key %d missing %s", id, i, f)
			}
		}
	}
}
